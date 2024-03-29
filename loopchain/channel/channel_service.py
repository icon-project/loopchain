# Copyright 2018 ICON Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import asyncio
import logging
import signal
import traceback

from loopchain import configure as conf
from loopchain import utils
from loopchain.baseservice import (BroadcastScheduler, BroadcastSchedulerFactory, ObjectManager, CommonSubprocess,
                                   RestClient, NodeSubscriber, UnregisteredException, TimerService)
from loopchain.blockchain.blocks import Block
from loopchain.blockchain.exception import AnnounceNewBlockError, WritePrecommitStateError
from loopchain.blockchain.types import ExternalAddress, TransactionStatusInQueue
from loopchain.blockchain.types import Hash32
from loopchain.channel.channel_inner_service import ChannelInnerService
from loopchain.channel.channel_property import ChannelProperty
from loopchain.channel.channel_statemachine import ChannelStateMachine
from loopchain.crypto.signature import Signer
from loopchain.peer import BlockManager
from loopchain.protos import loopchain_pb2
from loopchain.store.key_value_store import KeyValueStoreError
from loopchain.utils import loggers, command_arguments
from loopchain.utils.icon_service import convert_params, ParamType
from loopchain.utils.message_queue import StubCollection


class ChannelService:
    def __init__(self, channel_name, amqp_target, amqp_key, rollback=False):
        self.__block_manager: BlockManager = None
        self.__score_container: CommonSubprocess = None
        self.__score_info: dict = None
        self.__peer_auth: Signer = None
        self.__broadcast_scheduler: BroadcastScheduler = None
        self.__rs_client: RestClient = None
        self.__timer_service = TimerService()
        self.__node_subscriber: NodeSubscriber = None
        self._closing: bool = False
        self._rollback: bool = rollback

        loggers.get_preset().channel_name = channel_name
        loggers.get_preset().update_logger()

        channel_queue_name = conf.CHANNEL_QUEUE_NAME_FORMAT.format(channel_name=channel_name, amqp_key=amqp_key)
        self.__inner_service = ChannelInnerService(
            amqp_target, channel_queue_name, conf.AMQP_USERNAME, conf.AMQP_PASSWORD, channel_service=self)

        logging.info(f"ChannelService : {channel_name}, Queue : {channel_queue_name}")

        ChannelProperty().name = channel_name
        ChannelProperty().amqp_target = amqp_target
        ChannelProperty().crep_root_hash = Hash32.fromhex(conf.CHANNEL_OPTION[channel_name].get('crep_root_hash'))

        StubCollection().amqp_key = amqp_key
        StubCollection().amqp_target = amqp_target

        command_arguments.add_raw_command(command_arguments.Type.Channel, channel_name)
        command_arguments.add_raw_command(command_arguments.Type.AMQPTarget, amqp_target)
        command_arguments.add_raw_command(command_arguments.Type.AMQPKey, amqp_key)

        ObjectManager().channel_service = self
        self.__state_machine = ChannelStateMachine(self)

    @property
    def block_manager(self):
        return self.__block_manager

    @property
    def score_container(self):
        return self.__score_container

    @property
    def score_info(self):
        return self.__score_info

    @property
    def rs_client(self):
        return self.__rs_client

    @property
    def broadcast_scheduler(self):
        return self.__broadcast_scheduler

    @property
    def timer_service(self):
        return self.__timer_service

    @property
    def state_machine(self):
        return self.__state_machine

    @property
    def inner_service(self):
        return self.__inner_service

    @property
    def node_subscriber(self):
        return self.__node_subscriber

    def serve(self):
        async def _serve():
            await StubCollection().create_peer_stub()

            results = await StubCollection().peer_stub.async_task().get_node_info_detail()
            self._init_properties(**results)

            await self._init()
            self.__timer_service.start()
            self.__state_machine.complete_init_components()
            logging.info(f'init complete channel: {ChannelProperty().name}, '
                         f'state({self.__state_machine.state})')

        loop = self.__inner_service.loop
        serve_coroutine = _serve() if not self._rollback else self._serve_manual_rollback()
        loop.create_task(serve_coroutine)
        loop.add_signal_handler(signal.SIGINT, self.close, signal.SIGINT)
        loop.add_signal_handler(signal.SIGTERM, self.close, signal.SIGTERM)

        try:
            loop.run_forever()
        except Exception as e:
            utils.logger.exception(f"{e!r}")
        finally:
            self._shutdown(loop)
            self._cancel_tasks(loop)
            self._cleanup()
            loop.close()

    async def _serve_manual_rollback(self):
        """Initialize minimum channel resources and manual rollback

        :return: None
        """
        await StubCollection().create_peer_stub()

        results = await StubCollection().peer_stub.async_task().get_node_info_detail()
        self._init_properties(**results)

        self.__init_block_manager()
        await self.__init_score_container()
        await self.__inner_service.connect(conf.AMQP_CONNECTION_ATTEMPTS, conf.AMQP_RETRY_DELAY, exclusive=True)
        await asyncio.sleep(0.01)   # sleep to complete peer service initialization

        message = self._manual_rollback()
        self.shutdown_peer(message=message)

    def _manual_rollback(self) -> str:
        logging.debug("start manual rollback")
        if self.block_manager.blockchain.block_height >= 0:
            self.block_manager.rebuild_block()

        if self.block_manager.request_rollback():
            message = "rollback finished"
        else:
            message = "rollback cancelled"

        logging.debug("end manual rollback")
        return message

    def close(self, signum=None):
        utils.logger.info(f"signum = {repr(signum)}")
        if self._closing:
            utils.logger.info(f"already close progressing...")
            return

        self._closing = True

        if self.inner_service:
            self.inner_service.cleanup()

        self.inner_service.loop.stop()

    def _shutdown(self, loop):
        tasks = []
        if self.node_subscriber:
            tasks.append(loop.create_task(self.node_subscriber.shutdown()))

        tasks.append(loop.create_task(self.inner_service.shutdown()))
        tasks.append(loop.create_task(loop.shutdown_asyncgens()))

        try:
            loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))
        except RuntimeError as e:
            logging.debug(f"shutdown error : {e!r}")

        for task in tasks:
            if task.cancelled():
                continue
            if task.exception() is not None:
                logging.info(f"task : {task}, error : {task.exception()!r}")

    @staticmethod
    def _cancel_tasks(loop):
        logging.info(f"cancel tasks: loop={loop}")
        all_tasks = asyncio.Task.all_tasks(loop)
        for task in all_tasks:
            if task.done():
                continue
            task.cancel()

            try:
                logging.debug(f"waiting cancel complete={task}")
                loop.run_until_complete(task)
                logging.debug(f"done cancel complete={task}")
            except asyncio.CancelledError as e:
                logging.info(f"task : {task}, cancelled error : {e!r}")
            except Exception as e:
                logging.info(f"task : {task}, error : {e!r}")

        logging.info(f"cancel tasks done.")

    def _cleanup(self):
        utils.logger.info("Channel Resources.")

        if self.__timer_service.is_run():
            self.__timer_service.stop()
            self.__timer_service.wait()
            utils.logger.info("TimerService.")

        if self.__score_container:
            self.__score_container.stop()
            self.__score_container.wait()
            self.__score_container = None
            utils.logger.info("ScoreContainer.")

        if self.__broadcast_scheduler:
            self.__broadcast_scheduler.stop()
            self.__broadcast_scheduler.wait()
            self.__broadcast_scheduler = None
            utils.logger.info("BroadcastScheduler.")

        if self.__block_manager:
            self.__block_manager.stop()
            self.__block_manager = None
            utils.logger.info("BlockManager.")

    @staticmethod
    def _init_properties(**kwargs):
        """Initialize properties

        :param kwargs: takes (peer_id, peer_port, peer_target, rest_target)
        within parameters
        :return: None
        """
        loggers.get_preset().peer_id = kwargs.get('peer_id')
        loggers.get_preset().update_logger()

        ChannelProperty().peer_port = kwargs.get('peer_port')
        ChannelProperty().peer_target = kwargs.get('peer_target')
        ChannelProperty().rest_target = kwargs.get('rest_target')
        ChannelProperty().peer_id = kwargs.get('peer_id')
        ChannelProperty().peer_address = ExternalAddress.fromhex_address(ChannelProperty().peer_id)
        ChannelProperty().node_type = conf.NodeType.CitizenNode
        ChannelProperty().rs_target = None

    async def _init(self):
        """Initialize channel resources

        :return: None
        """
        await self.__init_peer_auth()
        self.__init_broadcast_scheduler()
        self.__init_block_manager()

        await self.__init_score_container()
        await self.__inner_service.connect(conf.AMQP_CONNECTION_ATTEMPTS, conf.AMQP_RETRY_DELAY, exclusive=True)
        await self.__init_sub_services()

    async def evaluate_network(self):
        await self._init_rs_client()
        self.__block_manager.blockchain.init_crep_reps()
        await self._select_node_type()
        self.__ready_to_height_sync()

        if conf.RECOVERY_MODE:
            if self.block_manager.preps_contain(ChannelProperty().peer_address):
                self.state_machine.recovery()
                return

            conf.RECOVERY_MODE = False

        self.state_machine.block_sync()

    async def recovery(self):
        from loopchain.tools.recovery import Recovery
        recovery = Recovery(ChannelProperty().name, self.block_manager.blockchain.block_height)
        recovery.set_target_list(self.block_manager.get_target_list())
        await recovery.fill_quorum()

        self.state_machine.recovery_block_sync()

    async def subscribe_network(self):
        await self._select_node_type()

        if self.is_support_node_function(conf.NodeFunction.Vote):
            await self.set_peer_type_in_channel()
        else:
            await self._init_rs_target()
            if ChannelProperty().rs_target is None:
                return
            self.__init_node_subscriber()
            await self.subscribe_to_parent()

        if self.__block_manager.is_shutdown_block():
            self.__state_machine.suspend()
        else:
            self.__state_machine.complete_subscribe()

            if self.is_support_node_function(conf.NodeFunction.Vote):
                self.turn_on_leader_complain_timer()

    def suspend(self):
        self.stop_leader_complain_timer()

    def update_nid(self):
        nid = self.__block_manager.blockchain.find_nid()
        self.__inner_service.update_sub_services_properties(nid=int(nid, 16))

    def _get_node_type_by_peer_list(self):
        epoch = self.block_manager.epoch
        if epoch:
            reps = self.__block_manager.blockchain.find_preps_addresses_by_roothash(
                epoch.reps_hash)
        else:
            reps = self.__block_manager.blockchain.find_preps_addresses_by_roothash(
                ChannelProperty().crep_root_hash)

        if ChannelProperty().peer_address in reps:
            return conf.NodeType.CommunityNode
        return conf.NodeType.CitizenNode

    def _is_role_switched(self) -> bool:
        new_node_type = self._get_node_type_by_peer_list()
        if new_node_type == ChannelProperty().node_type:
            utils.logger.debug(f"By peer manager, maintains the current node type({ChannelProperty().node_type})")
            return False

        return True

    async def _select_node_type(self):
        if self._is_role_switched():
            new_node_type = self._get_node_type_by_peer_list()
            utils.logger.info(f"Role switching to new node type: {new_node_type.name}")
            ChannelProperty().node_type = new_node_type
        self.__inner_service.update_sub_services_properties(node_type=ChannelProperty().node_type.value)

    def switch_role(self):
        self.__block_manager.blockchain.reset_leader_made_block_count(need_check_switched_role=True)
        if self._is_role_switched():
            self.__state_machine.switch_role()

    async def reset_network(self):
        utils.logger.info("Reset network")
        self.__timer_service.clean(except_key=TimerService.TIMER_KEY_BROADCAST_SEND_UNCONFIRMED_BLOCK)
        self.__rs_client = None
        self.__state_machine.evaluate_network()

    async def __init_peer_auth(self):
        try:
            node_key: bytes = await StubCollection().peer_stub.async_task().get_node_key()
            self.__peer_auth = Signer.from_prikey(node_key)
            ChannelProperty().peer_auth = self.__peer_auth
        except Exception as e:
            utils.exit_and_msg(f"peer auth init fail cause : {e}")

    def __init_block_manager(self):
        logging.debug(f"channel({ChannelProperty().name})")

        channel_name = ChannelProperty().name
        develop = command_arguments.command_values.get(command_arguments.Type.Develop, False)
        store_id = f"{ChannelProperty().peer_port}_{channel_name}" if develop else channel_name
        try:
            self.__block_manager = BlockManager(
                channel_service=self,
                peer_id=ChannelProperty().peer_id,
                channel_name=channel_name,
                store_id=store_id
            )
        except KeyValueStoreError as e:
            utils.exit_and_msg("KeyValueStoreError(" + str(e) + ")")

    def __init_broadcast_scheduler(self):
        scheduler = BroadcastSchedulerFactory.new(channel=ChannelProperty().name,
                                                  self_target=ChannelProperty().peer_target)
        scheduler.start()
        self.__broadcast_scheduler = scheduler

    def _get_radiostations(self):
        radiostations: list = self.get_channel_option().get('radiostations')
        utils.logger.debug(f"[_get_radiostations]: {radiostations}")
        if not radiostations:
            logging.warning(f"no configurations for radiostations.")
            return None

        radiostations = utils.convert_local_ip_to_private_ip(radiostations)
        try:
            radiostations.remove(ChannelProperty().rest_target)
            utils.logger.debug(f"[remove rest_target]: {ChannelProperty().rest_target}")
        except ValueError:
            pass

        return radiostations

    async def _init_rs_target(self, refresh_all: bool = False):
        if refresh_all:
            radiostations = self._get_radiostations()
            if radiostations is None:
                return
            await self.__rs_client.init(radiostations)
        else:
            try:
                self.__rs_client.init_next_target()
            except StopIteration:
                return await self._init_rs_target(refresh_all=True)

        ChannelProperty().rs_target = self.__rs_client.target
        self.__inner_service.update_sub_services_properties(relay_target=ChannelProperty().rs_target)

    async def _init_rs_client(self):
        self.__rs_client = RestClient(channel=ChannelProperty().name)
        await self._init_rs_target(refresh_all=True)

    async def __init_score_container(self):
        """create score container and save score_info and score_stub
        """
        try:
            self.__score_info = await self.__run_score_container()
        except BaseException as e:
            logging.exception(f"{e!r}")
            utils.exit_and_msg(f"run_score_container failed!!")

    async def __init_sub_services(self):
        self.__inner_service.init_sub_services()
        await StubCollection().create_channel_tx_creator_stub(ChannelProperty().name)
        await StubCollection().create_channel_tx_receiver_stub(ChannelProperty().name)

    def __init_node_subscriber(self):
        self.__node_subscriber = NodeSubscriber(
            channel=ChannelProperty().name,
            rs_target=ChannelProperty().rs_target
        )

    async def __run_score_container(self):
        if conf.RUN_ICON_IN_LAUNCHER:
            process_args = ['python3', '-m', 'loopchain', 'score',
                            '--channel', ChannelProperty().name]
            process_args += command_arguments.get_raw_commands_by_filter(
                command_arguments.Type.AMQPTarget,
                command_arguments.Type.AMQPKey,
                command_arguments.Type.Develop,
                command_arguments.Type.ConfigurationFilePath,
                command_arguments.Type.RadioStationTarget
            )
            self.__score_container = CommonSubprocess(process_args)

        await StubCollection().create_icon_score_stub(ChannelProperty().name)
        await StubCollection().icon_score_stubs[ChannelProperty().name].connect()
        await StubCollection().icon_score_stubs[ChannelProperty().name].async_task().hello()
        return None

    def is_support_node_function(self, node_function):
        return conf.NodeType.is_support_node_function(node_function, ChannelProperty().node_type)

    def get_channel_option(self) -> dict:
        return conf.CHANNEL_OPTION[ChannelProperty().name]

    def generate_genesis_block(self):
        if self.__block_manager.blockchain.block_height > -1:
            logging.debug("genesis block was already generated")
            return

        reps = self.block_manager.blockchain.find_preps_addresses_by_roothash(ChannelProperty().crep_root_hash)
        self.__block_manager.blockchain.generate_genesis_block(reps)

    async def subscribe_to_parent(self):
        def _handle_exception(future: asyncio.Future):
            exc = future.exception()
            logging.debug(f"error: {exc!r}")

            if ChannelProperty().node_type != conf.NodeType.CitizenNode:
                logging.debug(f"This node is not Citizen anymore.")
                return

            if isinstance(exc, AnnounceNewBlockError):
                self.__state_machine.block_sync()
                return

            if exc:
                if (self.__state_machine.state != "SubscribeNetwork"
                        or isinstance(exc, UnregisteredException)):
                    self.__state_machine.subscribe_network()
                else:
                    logging.warning(f"Waiting for next subscribe request...")

        utils.logger.spam(f"try subscribe_call_by_citizen target({ChannelProperty().rest_target})")
        subscribe_event = asyncio.Event()
        # try websocket connection, and handle exception in callback
        task = asyncio.ensure_future(
            self.__node_subscriber.start(
                block_height=self.__block_manager.blockchain.block_height,
                event=subscribe_event
            ),
            loop=self.__inner_service.loop
        )
        task.add_done_callback(_handle_exception)

        await subscribe_event.wait()

    def shutdown_peer(self, **kwargs):
        logging.debug(f"kwargs = {kwargs}")
        StubCollection().peer_stub.sync_task().stop(message=kwargs['message'])

    def set_peer_type(self, peer_type):
        """Set peer type when peer init only

        :param peer_type:
        :return:
        """
        self.__block_manager.set_peer_type(peer_type)

    async def set_peer_type_in_channel(self):
        peer_type = loopchain_pb2.PEER
        leader_id = self.__block_manager.get_next_leader()
        utils.logger.info(f"channel({ChannelProperty().name}) peer_leader: {leader_id}")

        logger_preset = loggers.get_preset()
        if ChannelProperty().peer_id == leader_id:
            logger_preset.is_leader = True
            utils.logger.info(f"Set Peer Type Leader! channel({ChannelProperty().name})")
            peer_type = loopchain_pb2.BLOCK_GENERATOR
        else:
            logger_preset.is_leader = False
        logger_preset.update_logger()

        self.__block_manager.set_peer_type(peer_type)

    def _is_genesis_node(self):
        return ('genesis_data_path' in self.get_channel_option()
                and self.is_support_node_function(conf.NodeFunction.Vote))

    def __ready_to_height_sync(self):
        if self.block_manager.blockchain.block_height >= 0:
            self.block_manager.rebuild_block()
        else:
            if self._is_genesis_node():
                self.generate_genesis_block()

        if not self.is_support_node_function(conf.NodeFunction.Vote) and not ChannelProperty().rs_target:
            utils.exit_and_msg(f"There's no radiostation target to sync block.")

    def reset_leader(self, new_leader_id, block_height=0, complained=False):
        """

        :param new_leader_id:
        :param block_height:
        :param complained:
        :return:
        """

        blockchain = self.__block_manager.blockchain
        prep_targets = blockchain.find_preps_targets_by_roothash(self.__block_manager.epoch.reps_hash)
        if ChannelProperty().peer_id not in prep_targets:
            if self.is_support_node_function(conf.NodeFunction.Vote):
                utils.logger.warning(f"This peer needs to switch to citizen.")
            return

        leader_peer_target = prep_targets.get(new_leader_id, None)

        if block_height > 0 and block_height != self.block_manager.blockchain.last_block.header.height + 1:
            utils.logger.warning(f"height behind peer can not take leader role. block_height({block_height}), "
                                 f"last_block.header.height("
                                 f"{self.block_manager.blockchain.last_block.header.height})")
            return

        if leader_peer_target is None:
            logging.warning(f"There is no peer by peer_id({new_leader_id})")
            return

        utils.logger.spam(f"target({leader_peer_target}), complained={complained}")

        if complained:
            self.__block_manager.blockchain.reset_leader_made_block_count()
            self.__block_manager.epoch.new_round(new_leader_id)

        if ChannelProperty().peer_id == new_leader_id:
            utils.logger.debug("Set Peer Type Leader!")
            peer_type = loopchain_pb2.BLOCK_GENERATOR
            self.state_machine.turn_to_leader()
        else:
            utils.logger.debug("Set Peer Type Peer!")
            peer_type = loopchain_pb2.PEER
            self.state_machine.turn_to_peer()

        self.__block_manager.set_peer_type(peer_type)
        self.turn_on_leader_complain_timer()

    def score_write_precommit_state(self, block: Block):
        logging.debug(f"call score commit {ChannelProperty().name} {block.header.height} {block.header.hash.hex()}")

        new_block_hash = block.header.hash
        try:
            old_block_hash = self.__block_manager.get_old_block_hash(block.header.height, new_block_hash)
        except KeyError:
            old_block_hash = new_block_hash

        logging.debug(f"Block Hash : {old_block_hash} -> {new_block_hash}")
        request = {
            "blockHeight": block.header.height,
            "oldBlockHash": old_block_hash.hex(),
            "newBlockHash": new_block_hash.hex()
        }
        request = convert_params(request, ParamType.write_precommit_state)

        stub = StubCollection().icon_score_stubs[ChannelProperty().name]
        precommit_result: dict = stub.sync_task().write_precommit_state(request)
        if "error" in precommit_result:
            raise WritePrecommitStateError(precommit_result['error'])

        self.__block_manager.pop_old_block_hashes(block.header.height)
        return True

    def callback_leader_complain_timeout(self):
        if self.state_machine.state == "BlockGenerate":
            _, new_leader_id = self.block_manager.get_leader_ids_for_complaint()
            if new_leader_id == ChannelProperty().peer_id:
                utils.logger.debug(
                    f"Cannot convert the state to the `LeaderComplain` from the `BlockGenerate`"
                    f", because I'm the BlockGenerate and the next leader candidate.")
                return

        self.state_machine.leader_complain()

    def turn_on_leader_complain_timer(self):
        """Turn on a leader complaint timer by the configuration name of `ALLOW_MAKE_EMPTY_BLOCK`.
        """
        if conf.ALLOW_MAKE_EMPTY_BLOCK:
            self.reset_leader_complain_timer()
        else:
            self.start_leader_complain_timer_if_tx_exists()

    def reset_leader_complain_timer(self):
        utils.logger.debug(f"round={self.__block_manager.epoch.round}, "
                           f"complain_duration={self.__block_manager.epoch.complain_duration})")

        if self.__timer_service.get_timer(TimerService.TIMER_KEY_LEADER_COMPLAIN):
            utils.logger.spam(f"Try to stop leader complaint timer for reset.")
            self.stop_leader_complain_timer()

        self.start_leader_complain_timer()

    def start_leader_complain_timer_if_tx_exists(self):
        if not self.block_manager.get_tx_queue().is_empty_in_status(TransactionStatusInQueue.normal):
            utils.logger.debug("Start leader complain timer because unconfirmed tx exists.")
            self.start_leader_complain_timer()

    def start_leader_complain_timer(self, duration=None):
        if duration is None:
            duration = self.__block_manager.epoch.complain_duration
        utils.logger.debug(f"round={self.block_manager.epoch.round}, duration={duration}")
        if self.state_machine.state in ("Vote", "LeaderComplain"):
            self.__timer_service.add_timer_convenient(timer_key=TimerService.TIMER_KEY_LEADER_COMPLAIN,
                                                      duration=duration,
                                                      is_repeat=True, callback=self.callback_leader_complain_timeout)

    def stop_leader_complain_timer(self):
        utils.logger.debug(f"Stop leader complain timer")
        self.__timer_service.stop_timer(TimerService.TIMER_KEY_LEADER_COMPLAIN)

    def start_subscribe_timer(self):
        self.__timer_service.add_timer_convenient(timer_key=TimerService.TIMER_KEY_SUBSCRIBE,
                                                  duration=conf.SUBSCRIBE_RETRY_TIMER,
                                                  is_repeat=True, callback=self.subscribe_network)

    def stop_subscribe_timer(self):
        self.__timer_service.stop_timer(TimerService.TIMER_KEY_SUBSCRIBE)

    def start_shutdown_timer_when_fail_subscribe(self):
        error = f"Shutdown by Subscribe retry timeout({conf.SHUTDOWN_TIMER} sec)"
        self.__timer_service.add_timer_convenient(timer_key=TimerService.TIMER_KEY_SHUTDOWN_WHEN_FAIL_SUBSCRIBE,
                                                  duration=conf.SHUTDOWN_TIMER, callback=self.shutdown_peer,
                                                  callback_kwargs={"message": error})

    def stop_shutdown_timer_when_fail_subscribe(self):
        self.__timer_service.stop_timer(TimerService.TIMER_KEY_SHUTDOWN_WHEN_FAIL_SUBSCRIBE)

    def start_block_monitoring_timer(self):
        self.__timer_service.add_timer_convenient(timer_key=TimerService.TIMER_KEY_BLOCK_MONITOR,
                                                  duration=conf.TIMEOUT_FOR_BLOCK_MONITOR,
                                                  callback=self.state_machine.subscribe_network)

    def reset_block_monitoring_timer(self):
        if self.__timer_service.get_timer(TimerService.TIMER_KEY_BLOCK_MONITOR):
            self.__timer_service.reset_timer(TimerService.TIMER_KEY_BLOCK_MONITOR)

    def stop_block_monitoring_timer(self):
        self.__timer_service.stop_timer(TimerService.TIMER_KEY_BLOCK_MONITOR)

    def stop_ws_heartbeat_timer(self):
        self.__timer_service.stop_timer(TimerService.TIMER_KEY_WS_HEARTBEAT)
