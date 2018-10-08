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

import json
import logging
import pickle
import leveldb
import signal
import time
import traceback

from earlgrey import MessageQueueService

import loopchain.utils as util
from loopchain import configure as conf
from loopchain.baseservice import BroadcastScheduler, BroadcastCommand, ObjectManager, CommonSubprocess
from loopchain.baseservice import StubManager, PeerManager, PeerStatus, TimerService, RestStubManager, Timer
from loopchain.blockchain import Block
from loopchain.channel.channel_inner_service import ChannelInnerService
from loopchain.channel.channel_property import ChannelProperty
from loopchain.consensus import Consensus, Acceptor, Proposer
from loopchain.peer import BlockManager
from loopchain.peer.consensus_default import ConsensusDefault
from loopchain.peer.consensus_lft import ConsensusLFT
from loopchain.peer.consensus_none import ConsensusNone
from loopchain.peer.consensus_siever import ConsensusSiever
from loopchain.peer.icx_authorization import IcxAuthorization
from loopchain.peer.peer_authorization import PeerAuthorization
from loopchain.protos import loopchain_pb2_grpc, message_code, loopchain_pb2
from loopchain.utils import loggers, command_arguments
from loopchain.utils.message_queue import StubCollection
from loopchain.utils.icon_service import convert_params, ParamType, response_to_json_query


class ChannelService:
    def __init__(self, channel_name, amqp_target, amqp_key):
        self.__block_manager: BlockManager = None
        self.__score_container: CommonSubprocess = None
        self.__score_info: dict = None
        self.__peer_auth: PeerAuthorization = None
        self.__peer_manager: PeerManager = None
        self.__broadcast_scheduler: BroadcastScheduler = None
        self.__radio_station_stub = None
        self.__consensus: Consensus = None
        self.__proposer: Proposer = None
        self.__acceptor: Acceptor = None
        self.__timer_service = TimerService()

        loggers.get_preset().channel_name = channel_name
        loggers.get_preset().update_logger()

        channel_queue_name = conf.CHANNEL_QUEUE_NAME_FORMAT.format(channel_name=channel_name, amqp_key=amqp_key)
        self.__inner_service = ChannelInnerService(
            amqp_target, channel_queue_name, conf.AMQP_USERNAME, conf.AMQP_PASSWORD, channel_service=self)

        logging.info(f"ChannelService : {channel_name}, Queue : {channel_queue_name}")

        ChannelProperty().name = channel_name
        ChannelProperty().amqp_target = amqp_target

        StubCollection().amqp_key = amqp_key
        StubCollection().amqp_target = amqp_target

        command_arguments.add_raw_command(command_arguments.Type.Channel, channel_name)
        command_arguments.add_raw_command(command_arguments.Type.AMQPTarget, amqp_target)
        command_arguments.add_raw_command(command_arguments.Type.AMQPKey, amqp_key)

        ObjectManager().channel_service = self

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
    def radio_station_stub(self):
        return self.__radio_station_stub

    @property
    def peer_auth(self):
        return self.__peer_auth

    @property
    def peer_manager(self):
        return self.__peer_manager

    @property
    def broadcast_scheduler(self):
        return self.__broadcast_scheduler

    @property
    def consensus(self):
        return self.__consensus

    @property
    def acceptor(self):
        return self.__acceptor

    @property
    def timer_service(self):
        return self.__timer_service

    def serve(self):
        async def _serve():
            await StubCollection().create_peer_stub()
            results = await StubCollection().peer_stub.async_task().get_channel_info_detail(ChannelProperty().name)

            await self.init(*results)

            self.__timer_service.start()
            logging.info(f'channel_service: init complete channel: {ChannelProperty().name}')

        loop = MessageQueueService.loop
        loop.create_task(_serve())
        loop.add_signal_handler(signal.SIGINT, self.close)
        loop.add_signal_handler(signal.SIGTERM, self.close)

        try:
            loop.run_forever()
        finally:
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.close()

            self.cleanup()

    def close(self):
        MessageQueueService.loop.stop()

    def cleanup(self):
        logging.info("Cleanup Channel Resources.")

        if self.__block_manager:
            self.__block_manager.stop()
            self.__block_manager.wait()
            self.__block_manager = None
            logging.info("Cleanup BlockManager.")

        if self.__score_container:
            self.__score_container.stop()
            self.__score_container.wait()
            self.__score_container = None
            logging.info("Cleanup ScoreContainer.")

        if self.__broadcast_scheduler:
            self.__broadcast_scheduler.stop()
            self.__broadcast_scheduler.wait()
            self.__broadcast_scheduler = None
            logging.info("Cleanup BroadcastSchuduler.")

        if self.__consensus:
            self.__consensus.stop()
            self.__consensus.wait()
            logging.info("Cleanup Consensus.")

        if self.__timer_service.is_run():
            self.__timer_service.stop()
            self.__timer_service.wait()
            logging.info("Cleanup TimerSerivce.")

    async def init(self, peer_port, peer_target, rest_target, radio_station_target, peer_id, group_id, node_type, score_package):
        loggers.get_preset().peer_id = peer_id
        loggers.get_preset().update_logger()

        ChannelProperty().peer_port = peer_port
        ChannelProperty().peer_target = peer_target
        ChannelProperty().rest_target = rest_target
        ChannelProperty().radio_station_target = radio_station_target
        ChannelProperty().peer_id = peer_id
        ChannelProperty().group_id = group_id
        ChannelProperty().node_type = conf.NodeType(node_type)
        ChannelProperty().score_package = score_package

        self.__init_peer_auth()
        self.__init_block_manager()
        self.__init_broadcast_scheduler()
        self.__init_radio_station_stub()

        await self.__init_score_container()
        await self.__inner_service.connect(conf.AMQP_CONNECTION_ATTEMPS, conf.AMQP_RETRY_DELAY, exclusive=True)

        self.__peer_manager = PeerManager(ChannelProperty().name)

        if conf.CONSENSUS_ALGORITHM == conf.ConsensusAlgorithm.lft:
            util.logger.spam(f"init consensus !")
            # load consensus
            self.__init_consensus()
            # load proposer
            self.__init_proposer(peer_id=peer_id)
            # load acceptor
            self.__init_acceptor(peer_id=peer_id)
            
        if self.is_support_node_function(conf.NodeFunction.Vote):
            self.connect_to_radio_station()
        await self.set_peer_type_in_channel()

        self.generate_genesis_block()

        if conf.CONSENSUS_ALGORITHM == conf.ConsensusAlgorithm.lft:
            self.__consensus.change_epoch(precommit_block=self.__block_manager.get_blockchain().last_block)
            self.__consensus.start()
        elif conf.ALLOW_MAKE_EMPTY_BLOCK:
            self.block_manager.block_generation_scheduler.start()

    def __init_peer_auth(self):
        try:
            channel_authorization = IcxAuthorization if util.channel_use_icx(ChannelProperty().name) \
                else PeerAuthorization

            self.__peer_auth = channel_authorization(ChannelProperty().name)

        except Exception as e:
            logging.exception(f"peer auth init fail cause : {e}")
            util.exit_and_msg(f"peer auth init fail cause : {e}")

    def __init_block_manager(self):
        logging.debug(f"__load_block_manager_each channel({ChannelProperty().name})")
        try:
            self.__block_manager = BlockManager(
                channel_manager=self,
                peer_id=ChannelProperty().peer_id,
                channel_name=ChannelProperty().name,
                level_db_identity=ChannelProperty().peer_target
            )

            self.__block_manager.consensus_algorithm = self.__init_consensus_algorithm()

            if conf.CONSENSUS_ALGORITHM != conf.ConsensusAlgorithm.lft:
                self.__block_manager.start()

        except leveldb.LevelDBError as e:
            util.exit_and_msg("LevelDBError(" + str(e) + ")")

    def __init_consensus(self):
        consensus = Consensus(self, ChannelProperty().name)
        self.__consensus = consensus
        self.__block_manager.consensus = consensus
        consensus.multiple_register(self.__block_manager)

    def __init_proposer(self, peer_id: str):
        proposer = Proposer(
            name="loopchain.consensus.Proposer",
            peer_id=peer_id,
            channel=ChannelProperty().name,
            channel_service=self)
        self.__consensus.multiple_register(proposer)
        self.__proposer = proposer

    def __init_acceptor(self, peer_id: str):
        acceptor = Acceptor(
            name="loopchain.consensus.Acceptor",
            consensus=self.__consensus,
            peer_id=peer_id,
            channel=ChannelProperty().name,
            channel_service=self)
        self.__consensus.multiple_register(acceptor)
        self.__acceptor = acceptor

    def __init_broadcast_scheduler(self):
        scheduler = BroadcastScheduler(channel=ChannelProperty().name, self_target=ChannelProperty().peer_target)
        scheduler.start()

        self.__broadcast_scheduler = scheduler

        future = scheduler.schedule_job(BroadcastCommand.SUBSCRIBE, ChannelProperty().peer_target)
        future.result(conf.TIMEOUT_FOR_FUTURE)

    def __init_radio_station_stub(self):
        if self.is_support_node_function(conf.NodeFunction.Vote):
            self.__radio_station_stub = StubManager.get_stub_manager_to_server(
                ChannelProperty().radio_station_target,
                loopchain_pb2_grpc.RadioStationStub,
                conf.CONNECTION_RETRY_TIMEOUT_TO_RS,
                ssl_auth_type=conf.GRPC_SSL_TYPE)
        else:
            self.__radio_station_stub = RestStubManager(ChannelProperty().radio_station_target, ChannelProperty().name)

    async def __init_score_container(self):
        """create score container and save score_info and score_stub
        """
        for i in range(conf.SCORE_LOAD_RETRY_TIMES):
            try:
                self.__score_info = await self.__run_score_container()
            except BaseException as e:
                util.logger.spam(f"channel_manager:load_score_container_each score_info load fail retry({i})")
                logging.error(e)
                traceback.print_exc()
                time.sleep(conf.SCORE_LOAD_RETRY_INTERVAL)  # This blocking main thread is intended.

            else:
                break

    async def __run_score_container(self):
        if not conf.USE_EXTERNAL_SCORE or conf.EXTERNAL_SCORE_RUN_IN_LAUNCHER:
            process_args = ['python3', '-m', 'loopchain', 'score',
                            '--channel', ChannelProperty().name,
                            '--score_package', ChannelProperty().score_package]
            process_args += command_arguments.get_raw_commands_by_filter(
                command_arguments.Type.AMQPTarget,
                command_arguments.Type.AMQPKey,
                command_arguments.Type.Develop,
                command_arguments.Type.ConfigurationFilePath
            )
            self.__score_container = CommonSubprocess(process_args)

        if util.channel_use_icx(ChannelProperty().name):
            await StubCollection().create_icon_score_stub(ChannelProperty().name)
            await StubCollection().icon_score_stubs[ChannelProperty().name].connect()
            await StubCollection().icon_score_stubs[ChannelProperty().name].async_task().hello()
            return None
        else:
            await StubCollection().create_score_stub(ChannelProperty().name, ChannelProperty().score_package)
            await StubCollection().score_stubs[ChannelProperty().name].connect()
            await StubCollection().score_stubs[ChannelProperty().name].async_task().hello()

            return await self.__load_score()

    def __init_consensus_algorithm(self):
        """initialize a consensus algorithm by configuration.
        """
        if conf.CONSENSUS_ALGORITHM == conf.ConsensusAlgorithm.none:
            consensus_algorithm = ConsensusNone(self.__block_manager)
        elif conf.CONSENSUS_ALGORITHM == conf.ConsensusAlgorithm.siever:
            consensus_algorithm = ConsensusSiever(self.__block_manager)
        elif conf.CONSENSUS_ALGORITHM == conf.ConsensusAlgorithm.lft:
            consensus_algorithm = ConsensusLFT(self.__block_manager)
        else:
            consensus_algorithm = ConsensusDefault(self.__block_manager)

        return consensus_algorithm

    async def __load_score(self):
        channel_name = ChannelProperty().name
        score_package_name = ChannelProperty().score_package

        util.logger.spam(f"peer_service:__load_score --init--")
        logging.info("LOAD SCORE AND CONNECT TO SCORE SERVICE!")

        params = dict()
        params[message_code.MetaParams.ScoreLoad.repository_path] = conf.DEFAULT_SCORE_REPOSITORY_PATH
        params[message_code.MetaParams.ScoreLoad.score_package] = score_package_name
        params[message_code.MetaParams.ScoreLoad.base] = conf.DEFAULT_SCORE_BASE
        params[message_code.MetaParams.ScoreLoad.peer_id] = ChannelProperty().peer_id
        meta = json.dumps(params)
        logging.debug(f"load score params : {meta}")

        util.logger.spam(f"peer_service:__load_score --1--")
        score_stub = StubCollection().score_stubs[channel_name]
        response = await score_stub.async_task().score_load(meta)

        logging.debug("try score load on score service: " + str(response))
        if not response:
            return None

        if response.code != message_code.Response.success:
            util.exit_and_msg("Fail Get Score from Score Server...")
            return None

        logging.debug("Get Score from Score Server...")
        score_info = json.loads(response.meta)

        logging.info("LOAD SCORE DONE!")
        util.logger.spam(f"peer_service:__load_score --end--")

        return score_info

    def is_support_node_function(self, node_function):
        return conf.NodeType.is_support_node_function(node_function, ChannelProperty().node_type)

    def get_channel_option(self) -> dict:
        channel_option = conf.CHANNEL_OPTION
        return channel_option[ChannelProperty().name]

    def generate_genesis_block(self):
        if self.block_manager.peer_type != loopchain_pb2.BLOCK_GENERATOR:
            return

        block_chain = self.block_manager.get_blockchain()
        if block_chain.block_height > -1:
            logging.debug("genesis block was already generated")
            return

        block_chain.generate_genesis_block()

    def connect_to_radio_station(self, is_reconnect=False):
        response = self.__radio_station_stub.call_in_times(
            method_name="ConnectPeer",
            message=loopchain_pb2.ConnectPeerRequest(
                channel=ChannelProperty().name,
                peer_object=b'',
                peer_id=ChannelProperty().peer_id,
                peer_target=ChannelProperty().peer_target,
                group_id=ChannelProperty().group_id,
                cert=self.peer_auth.peer_cert),
            retry_times=conf.CONNECTION_RETRY_TIMES_TO_RS,
            is_stub_reuse=True,
            timeout=conf.CONNECTION_TIMEOUT_TO_RS)

        # start next ConnectPeer timer
        if TimerService.TIMER_KEY_CONNECT_PEER not in self.__timer_service.timer_list.keys():
            self.__timer_service.add_timer(
                TimerService.TIMER_KEY_CONNECT_PEER,
                Timer(
                    target=TimerService.TIMER_KEY_CONNECT_PEER,
                    duration=conf.CONNECTION_RETRY_TIMER,
                    callback=self.connect_to_radio_station,
                    callback_kwargs={"is_reconnect": True}
                )
            )

        if is_reconnect:
            return

        if response and response.status == message_code.Response.success:
            peer_list_data = pickle.loads(response.peer_list)
            self.__peer_manager.load(peer_list_data, False)
            peers, peer_list = self.__peer_manager.get_peers_for_debug()
            logging.debug("peer list update: " + peers)

            # add connected peer to processes audience
            for each_peer in peer_list:
                util.logger.spam(f"peer_service:connect_to_radio_station peer({each_peer.target}-{each_peer.status})")
                if each_peer.status == PeerStatus.connected:
                    self.__broadcast_scheduler.schedule_job(BroadcastCommand.SUBSCRIBE, each_peer.target)

    async def subscribe_to_radio_station(self):
        await self.__subscribe_call_to_stub_by_method(self.__radio_station_stub, loopchain_pb2.PEER)

    async def subscribe_to_target_stub(self, target_stub):
        await self.__subscribe_call_to_stub_by_method(target_stub, loopchain_pb2.PEER)

    async def subscribe_to_peer(self, peer_id, peer_type):
        peer = self.peer_manager.get_peer(peer_id)
        peer_stub = self.peer_manager.get_peer_stub_manager(peer)

        await self.__subscribe_call_to_stub_by_method(peer_stub, peer_type)
        self.__broadcast_scheduler.schedule_job(BroadcastCommand.SUBSCRIBE, peer_stub.target)

    async def __subscribe_call_to_stub_by_method(self, peer_stub, peer_type):
        if self.is_support_node_function(conf.NodeFunction.Vote):
            await peer_stub.call_async(
                "Subscribe",
                loopchain_pb2.PeerRequest(
                    channel=ChannelProperty().name,
                    peer_target=ChannelProperty().peer_target, peer_type=peer_type,
                    peer_id=ChannelProperty().peer_id, group_id=ChannelProperty().group_id,
                    node_type=ChannelProperty().node_type
                ),
            )
        else:
            util.logger.spam(f"channel_service:__subscribe_call_to_stub_by_method "
                             f"peer_target({ChannelProperty().rest_target})")
            response = self.__subscribe_call_to_rs_stub(peer_stub)

            if response['response_code'] != message_code.Response.success:
                error = f"subscribe fail to peer_target({ChannelProperty().radio_station_target}) " \
                        f"reason({response['message']})"
                await StubCollection().peer_stub.async_task().stop(message=error)

    def __subscribe_call_to_rs_stub(self, rs_rest_stub):
        response = {'response_code': message_code.Response.fail,
                    'message': message_code.get_response_msg(message_code.Response.fail)}

        try:
            if conf.REST_SSL_TYPE == conf.SSLAuthType.none:
                peer_target = ChannelProperty().rest_target
            else:
                peer_target = f"https://{ChannelProperty().rest_target}"
            response = rs_rest_stub.call(
                "Subscribe", {
                    'channel': ChannelProperty().name,
                    'peer_target': peer_target
                }
            )

        except Exception as e:
            logging.warning(f"Due to Subscription fail to RadioStation(mother peer), "
                            f"automatically retrying subscribe call")

        if response['response_code'] == message_code.Response.success:
            if TimerService.TIMER_KEY_SUBSCRIBE in self.__timer_service.timer_list.keys():
                self.__timer_service.stop_timer(TimerService.TIMER_KEY_SUBSCRIBE)
                self.radio_station_stub.update_methods_version()
                logging.debug(f"Subscription to RadioStation(mother peer) is successful.")

            if TimerService.TIMER_KEY_SHUTDOWN_WHEN_FAIL_SUBSCRIBE in self.__timer_service.timer_list.keys():
                self.__timer_service.stop_timer(TimerService.TIMER_KEY_SHUTDOWN_WHEN_FAIL_SUBSCRIBE)

            # start next get_status timer
            timer_key = TimerService.TIMER_KEY_GET_LAST_BLOCK_KEEP_CITIZEN_SUBSCRIPTION
            if timer_key not in self.__timer_service.timer_list.keys():
                util.logger.spam(f"add timer for check_block_height_call to radiostation...")
                self.__timer_service.add_timer(
                    timer_key,
                    Timer(
                        target=timer_key,
                        duration=conf.GET_LAST_BLOCK_TIMER,
                        is_repeat=True,
                        callback=self.__check_block_height_call_to_rs_stub,
                        callback_kwargs={"rs_rest_stub": rs_rest_stub}
                    )
                )
        else:
            timer_key = TimerService.TIMER_KEY_SHUTDOWN_WHEN_FAIL_SUBSCRIBE
            if timer_key not in self.__timer_service.timer_list.keys():
                error = f"Shutdown by Subscribe retry timeout({conf.SHUTDOWN_TIMER})"
                self.__timer_service.add_timer(
                    timer_key,
                    Timer(
                        target=timer_key,
                        duration=conf.SHUTDOWN_TIMER,
                        callback=self.__shutdown_peer,
                        callback_kwargs={"message": error}
                    )
                )

        return response

    def __check_block_height_call_to_rs_stub(self, **kwargs):
        rs_rest_stub = kwargs.get("rs_rest_stub", None)
        response = dict()
        try:
            response = rs_rest_stub.call("GetLastBlock")
        except Exception as e:
            response['response_code'] = message_code.Response.fail

        if response['response_code'] == message_code.Response.success:
            if response['block']['height'] <= self.__block_manager.get_blockchain().block_height:
                # keep get last block timer, citizen subscription is still valid.
                return

        # citizen needs additional block or failed to connect to mother peer.
        timer_key = TimerService.TIMER_KEY_GET_LAST_BLOCK_KEEP_CITIZEN_SUBSCRIPTION
        if timer_key in self.__timer_service.timer_list.keys():
            util.logger.spam(f"stop timer for check_block_height_call to radiostation...")
            self.__timer_service.stop_timer(timer_key)

        timer_key = TimerService.TIMER_KEY_SUBSCRIBE
        if timer_key not in self.__timer_service.timer_list.keys():
            self.__timer_service.add_timer(
                timer_key,
                Timer(
                    target=timer_key,
                    duration=conf.SUBSCRIBE_RETRY_TIMER,
                    is_repeat=True,
                    callback=self.__subscribe_call_to_rs_stub,
                    callback_kwargs={"rs_rest_stub": rs_rest_stub}
                )
            )

    def __shutdown_peer(self, **kwargs):
        util.logger.spam(f"channel_service:__shutdown_peer")
        StubCollection().peer_stub.sync_task().stop(message=kwargs['message'])

    def set_peer_type(self, peer_type):
        """Set peer type when peer init only

        :param peer_type:
        :return:
        """
        self.__block_manager.set_peer_type(peer_type)

    def save_peer_manager(self, peer_manager):
        """peer_list 를 leveldb 에 저장한다.

        :param peer_manager:
        """
        level_db_key_name = str.encode(conf.LEVEL_DB_KEY_FOR_PEER_LIST)

        try:
            dump = peer_manager.dump()
            level_db = self.__block_manager.get_level_db()
            level_db.Put(level_db_key_name, dump)
        except AttributeError as e:
            logging.warning("Fail Save Peer_list: " + str(e))

    async def set_peer_type_in_channel(self):
        peer_type = loopchain_pb2.PEER
        peer_leader = self.peer_manager.get_leader_peer(
            is_complain_to_rs=self.is_support_node_function(conf.NodeFunction.Vote))
        logging.debug(f"channel({ChannelProperty().name}) peer_leader: " + str(peer_leader))

        logger_preset = loggers.get_preset()
        if self.is_support_node_function(conf.NodeFunction.Vote) and ChannelProperty().peer_id == peer_leader.peer_id:
            logger_preset.is_leader = True
            logging.debug(f"Set Peer Type Leader! channel({ChannelProperty().name})")
            peer_type = loopchain_pb2.BLOCK_GENERATOR
        else:
            logger_preset.is_leader = False
        logger_preset.update_logger()

        if conf.CONSENSUS_ALGORITHM == conf.ConsensusAlgorithm.lft:
            self.consensus.leader_id = peer_leader.peer_id

        if peer_type == loopchain_pb2.BLOCK_GENERATOR:
            self.block_manager.set_peer_type(peer_type)
            self.__ready_to_height_sync(True)
            await self.subscribe_to_radio_station()
        elif peer_type == loopchain_pb2.PEER:
            self.__ready_to_height_sync(False)
            await self.__block_height_sync_channel()

    def __ready_to_height_sync(self, is_leader: bool = False):
        block_chain = self.block_manager.get_blockchain()

        block_chain.init_block_chain(is_leader)
        if block_chain.block_height > -1:
            self.block_manager.rebuild_block()

    async def __block_height_sync_channel(self):
        # leader 로 시작하지 않았는데 자신의 정보가 leader Peer 정보이면 block height sync 하여
        # 최종 블럭의 leader 를 찾는다.
        peer_manager = self.peer_manager
        peer_leader = peer_manager.get_leader_peer()
        self_peer_object = peer_manager.get_peer(ChannelProperty().peer_id)
        is_delay_announce_new_leader = False
        peer_old_leader = None

        if peer_leader:
            block_sync_target = peer_leader.target
            block_sync_target_stub = StubManager.get_stub_manager_to_server(
                block_sync_target,
                loopchain_pb2_grpc.PeerServiceStub,
                time_out_seconds=conf.CONNECTION_RETRY_TIMEOUT,
                ssl_auth_type=conf.GRPC_SSL_TYPE
            )
        else:
            block_sync_target = ChannelProperty().radio_station_target
            block_sync_target_stub = self.__radio_station_stub

        if block_sync_target != ChannelProperty().peer_target:
            if block_sync_target_stub is None:
                logging.warning("You maybe Older from this network... or No leader in this network!")

                is_delay_announce_new_leader = True
                peer_old_leader = peer_leader
                peer_leader = self.peer_manager.leader_complain_to_rs(
                    conf.ALL_GROUP_ID, is_announce_new_peer=False)

                if peer_leader is not None and ChannelProperty().node_type == conf.NodeType.CommunityNode:
                    block_sync_target_stub = StubManager.get_stub_manager_to_server(
                        peer_leader.target,
                        loopchain_pb2_grpc.PeerServiceStub,
                        time_out_seconds=conf.CONNECTION_RETRY_TIMEOUT,
                        ssl_auth_type=conf.GRPC_SSL_TYPE
                    )

            if self.is_support_node_function(conf.NodeFunction.Vote) and \
                    (not peer_leader or peer_leader.peer_id == ChannelProperty().peer_id):
                peer_leader = self_peer_object
                self.block_manager.set_peer_type(loopchain_pb2.BLOCK_GENERATOR)
            else:
                _, future = self.block_manager.block_height_sync(block_sync_target_stub)
                await future

                self.show_peers()

            if is_delay_announce_new_leader and ChannelProperty().node_type == conf.NodeType.CommunityNode:
                self.peer_manager.announce_new_leader(
                    peer_old_leader.peer_id,
                    peer_leader.peer_id,
                    self_peer_id=ChannelProperty().peer_id)

    def show_peers(self):
        logging.debug(f"peer_service:show_peers ({ChannelProperty().name}): ")
        for peer in self.peer_manager.get_IP_of_peers_in_group():
            logging.debug("peer_target: " + peer)

    async def reset_leader(self, new_leader_id, block_height=0):
        logging.info(f"RESET LEADER channel({ChannelProperty().name}) leader_id({new_leader_id})")

        complained_leader = self.peer_manager.get_leader_peer()
        leader_peer = self.peer_manager.get_peer(new_leader_id, None)

        if block_height > 0 and block_height != self.block_manager.get_blockchain().last_block.height + 1:
            logging.warning(f"height behind peer can not take leader role.")
            return

        if leader_peer is None:
            logging.warning(f"in peer_service:reset_leader There is no peer by peer_id({new_leader_id})")
            return

        util.logger.spam(f"peer_service:reset_leader target({leader_peer.target})")

        self_peer_object = self.peer_manager.get_peer(ChannelProperty().peer_id)
        self.peer_manager.set_leader_peer(leader_peer, None)

        peer_leader = self.peer_manager.get_leader_peer()
        peer_type = loopchain_pb2.PEER

        if self_peer_object.target == peer_leader.target:
            loggers.get_preset().is_leader = True
            loggers.get_preset().update_logger()

            logging.debug("Set Peer Type Leader!")
            peer_type = loopchain_pb2.BLOCK_GENERATOR
            self.block_manager.get_blockchain().reset_made_block_count()
            self.peer_manager.announce_new_leader(
                complained_leader.peer_id, new_leader_id, is_broadcast=True, self_peer_id=ChannelProperty().peer_id)
        else:
            loggers.get_preset().is_leader = False
            loggers.get_preset().update_logger()

            logging.debug("Set Peer Type Peer!")
            # 새 leader 에게 subscribe 하기
            await self.subscribe_to_radio_station()
            await self.subscribe_to_peer(peer_leader.peer_id, loopchain_pb2.BLOCK_GENERATOR)

        # update candidate blocks
        self.block_manager.get_candidate_blocks().set_last_block(self.block_manager.get_blockchain().last_block)
        self.block_manager.set_peer_type(peer_type)

    def set_new_leader(self, new_leader_id, block_height=0):
        logging.info(f"SET NEW LEADER channel({ChannelProperty().name}) leader_id({new_leader_id})")

        # complained_leader = self.peer_manager.get_leader_peer()
        leader_peer = self.peer_manager.get_peer(new_leader_id, None)

        if block_height > 0 and block_height != self.block_manager.get_blockchain().last_block.height + 1:
            logging.warning(f"height behind peer can not take leader role.")
            return

        if leader_peer is None:
            logging.warning(f"in channel_service:set_new_leader::There is no peer by peer_id({new_leader_id})")
            return

        util.logger.spam(f"channel_service:set_new_leader::leader_target({leader_peer.target})")

        self_peer_object = self.peer_manager.get_peer(ChannelProperty().peer_id)
        self.peer_manager.set_leader_peer(leader_peer, None)

        peer_leader = self.peer_manager.get_leader_peer()

        if self_peer_object.target == peer_leader.target:
            loggers.get_preset().is_leader = True
            loggers.get_preset().update_logger()

            logging.debug("I'm Leader Peer!")
        else:
            loggers.get_preset().is_leader = False
            loggers.get_preset().update_logger()

            logging.debug("I'm general Peer!")
            # 새 leader 에게 subscribe 하기
            # await self.subscribe_to_radio_station()
            # await self.subscribe_to_peer(peer_leader.peer_id, loopchain_pb2.BLOCK_GENERATOR)

    def genesis_invoke(self, block: Block) -> dict or None:
        if util.channel_use_icx(ChannelProperty().name):
            method = "icx_sendTransaction"
            transactions = []
            for tx in block.confirmed_transaction_list:
                transaction = {
                    "method": method,
                    "params": {
                        "txHash": tx.tx_hash
                    },
                    "genesisData": tx.genesis_origin_data
                }
                transactions.append(transaction)

            request = {
                'block': {
                    'blockHeight': block.height,
                    'blockHash': block.block_hash,
                    'timestamp': block.time_stamp
                },
                'transactions': transactions
            }
            request = convert_params(request, ParamType.invoke)
            stub = StubCollection().icon_score_stubs[ChannelProperty().name]
            response = stub.sync_task().invoke(request)
            response_to_json_query(response)
            block.commit_state[ChannelProperty().name] = response['stateRootHash']
            return response["txResults"]
        else:
            block_object = pickle.dumps(block)
            stub = StubCollection().score_stubs[ChannelProperty().name]
            response = stub.sync_task().genesis_invoke(block_object)
            if response.code == message_code.Response.success:
                return json.loads(response.meta)

        return None

    def score_invoke(self, _block: Block) -> dict or None:
        if util.channel_use_icx(ChannelProperty().name):
            method = "icx_sendTransaction"
            transactions = []
            for tx in _block.confirmed_transaction_list:
                data = tx.icx_origin_data
                transaction = {
                    "method": method,
                    "params": data
                }
                transactions.append(transaction)

            request = {
                'block': {
                    'blockHeight': _block.height,
                    'blockHash': _block.block_hash,
                    'prevBlockHash': _block.prev_block_hash,
                    'timestamp': _block.time_stamp
                },
                'transactions': transactions
            }
            request = convert_params(request, ParamType.invoke)
            stub = StubCollection().icon_score_stubs[ChannelProperty().name]
            response = stub.sync_task().invoke(request)
            response_to_json_query(response)
            _block.commit_state[ChannelProperty().name] = response['stateRootHash']
            return response["txResults"]
        else:
            stub = StubCollection().score_stubs[ChannelProperty().name]
            response = stub.sync_task().score_invoke(_block)

            if response.code == message_code.Response.success:
                commit_state = pickle.loads(response.object)
                _block.commit_state = commit_state
                return json.loads(response.meta)

        return None

    def score_change_block_hash(self, block_height, old_block_hash, new_block_hash):
        change_hash_info = json.dumps({"block_height": block_height, "old_block_hash": old_block_hash,
                                       "new_block_hash": new_block_hash})

        if not util.channel_use_icx(ChannelProperty().name):
            stub = StubCollection().score_stubs[ChannelProperty().name]
            stub.sync_task().change_block_hash(change_hash_info)

    def score_write_precommit_state(self, block: Block):
        logging.debug(f"call score commit {ChannelProperty().name} {block.height} {block.block_hash}")

        if util.channel_use_icx(ChannelProperty().name):
            request = {
                "blockHeight": block.height,
                "blockHash": block.block_hash,
            }
            request = convert_params(request, ParamType.write_precommit_state)

            stub = StubCollection().icon_score_stubs[ChannelProperty().name]
            stub.sync_task().write_precommit_state(request)
            return True
        else:
            block_commit_info = json.dumps({"block_height": block.height, "block_hash": block.block_hash})
            stub = StubCollection().score_stubs[ChannelProperty().name]
            response = stub.sync_task().write_precommit_state(block_commit_info)

            if response.code == message_code.Response.success:
                return True
            else:
                logging.error(f"score db commit fail cause {response.message}")
                return False

    def score_remove_precommit_state(self, block: Block):
        if not util.channel_use_icx(ChannelProperty().name):
            request = {
                "blockHeight": block.height,
                "blockHash": block.block_hash,
            }
            request = convert_params(request, ParamType.remove_precommit_state)

            stub = StubCollection().icon_score_stubs[ChannelProperty().name]
            stub.sync_task().remove_precommit_state(request)

            return True
        else:
            invoke_fail_info = json.dumps({"block_height": block.height, "block_hash": block.block_hash})
            stub = StubCollection().score_stubs[ChannelProperty().name]
            stub.sync_task().remove_precommit_state(invoke_fail_info)
            return True

    def get_object_has_queue_by_consensus(self):
        if conf.CONSENSUS_ALGORITHM == conf.ConsensusAlgorithm.lft:
            object_has_queue = self.__consensus
        else:
            object_has_queue = self.__block_manager

        return object_has_queue
