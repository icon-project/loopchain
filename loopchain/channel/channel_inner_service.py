"""Channel Inner Service."""

import json
import multiprocessing as mp
import signal
from asyncio import Condition
from collections import namedtuple
from typing import Union, Dict, List, Tuple

from earlgrey import *
from pkg_resources import parse_version

from lft.consensus.events import ReceiveVoteEvent
from loopchain import configure as conf
from loopchain import utils as util
from loopchain.baseservice import (BroadcastCommand, BroadcastScheduler, BroadcastSchedulerFactory,
                                   ScoreResponse)
from loopchain.baseservice.module_process import ModuleProcess, ModuleProcessProperties
from loopchain.blockchain.blocks import Block, BlockSerializer
from loopchain.blockchain.exception import *
from loopchain.blockchain.transactions import (Transaction, TransactionSerializer, TransactionVerifier,
                                               TransactionVersioner)
from loopchain.blockchain.types import Hash32
from loopchain.blockchain.votes import Vote
from loopchain.channel.channel_property import ChannelProperty
from loopchain.jsonrpc.exception import JsonError
from loopchain.protos import message_code
from loopchain.qos.qos_controller import QosController, QosCountControl
from loopchain.utils.message_queue import StubCollection

if TYPE_CHECKING:
    from loopchain.channel.channel_service import ChannelService
    from lft.event import EventSystem


class ChannelTxCreatorInnerTask:
    def __init__(self, channel_name: str, peer_target: str, tx_versioner: TransactionVersioner):
        self.__channel_name = channel_name
        self.__properties = dict()
        self.__tx_versioner = tx_versioner

        scheduler = BroadcastSchedulerFactory.new(channel=channel_name,
                                                  self_target=peer_target,
                                                  is_multiprocessing=True)
        scheduler.start()
        self.__broadcast_scheduler = scheduler
        self.__qos_controller = QosController()
        self.__qos_controller.append(QosCountControl(limit_count=conf.TPS_LIMIT_PER_SEC))

    def __pre_validate(self, tx: Transaction):
        if not util.is_in_time_boundary(tx.timestamp, conf.TIMESTAMP_BOUNDARY_SECOND):
            raise TransactionOutOfTimeBound(tx, util.get_now_time_stamp())

    def cleanup(self):
        self.__broadcast_scheduler.stop()
        self.__broadcast_scheduler.wait()
        self.__broadcast_scheduler: BroadcastScheduler = None

    @message_queue_task
    async def update_properties(self, properties: dict):
        self.__properties.update(properties)

    @message_queue_task
    async def create_icx_tx(self, kwargs: dict):
        tx_hash = None
        relay_target = None
        if self.__qos_controller.limit():
            util.logger.debug(f"Out of TPS limit. tx={kwargs}")
            return message_code.Response.fail_out_of_tps_limit, tx_hash, relay_target

        node_type = self.__properties.get('node_type', None)
        if node_type is None:
            util.logger.warning("Node type has not been set yet.")
            return NodeInitializationError.message_code, tx_hash, relay_target
        elif node_type != conf.NodeType.CommunityNode.value:
            relay_target = self.__properties.get('relay_target', None)
            return message_code.Response.fail_no_permission, tx_hash, relay_target

        result_code = None
        exception = None
        tx = None

        try:
            tx_version, tx_type = self.__tx_versioner.get_version(kwargs)

            ts = TransactionSerializer.new(tx_version, tx_type, self.__tx_versioner)
            tx = ts.from_(kwargs)

            nid = self.__properties.get('nid', None)
            if nid is None:
                util.logger.warning(f"NID has not been set yet.")
                raise NodeInitializationError(tx.hash.hex())

            tv = TransactionVerifier.new(tx_version, tx_type, self.__tx_versioner)
            tv.pre_verify(tx, nid=nid)

            self.__pre_validate(tx)

            logging.debug(f"create icx input : {kwargs}")

            self.__broadcast_scheduler.schedule_job(BroadcastCommand.CREATE_TX, (tx, self.__tx_versioner))
            return message_code.Response.success, tx.hash.hex(), relay_target

        except MessageCodeError as e:
            result_code = e.message_code
            exception = e
            traceback.print_exc()
        except BaseException as e:
            result_code = TransactionInvalidError.message_code
            exception = e
            traceback.print_exc()
        finally:
            if exception:
                logging.warning(f"create_icx_tx: tx restore fail.\n\n"
                                f"kwargs({kwargs})\n\n"
                                f"tx({tx})\n\n"
                                f"exception({exception})")
                return result_code, tx_hash, relay_target

    async def schedule_job(self, command, params):
        self.__broadcast_scheduler.schedule_job(command, params)


class ChannelTxCreatorInnerService(MessageQueueService[ChannelTxCreatorInnerTask]):
    TaskType = ChannelTxCreatorInnerTask

    def __init__(self, broadcast_queue: mp.Queue, amqp_target, route_key, username=None, password=None, **task_kwargs):
        super().__init__(amqp_target, route_key, username, password, **task_kwargs)

        self.__is_running = True
        self.__broadcast_queue = broadcast_queue

        async def _stop_loop():
            self.loop.stop()

        def _schedule_job():
            while True:
                command, params = broadcast_queue.get()
                if not self.__is_running or command is None:
                    break
                asyncio.run_coroutine_threadsafe(self._task.schedule_job(command, params), self.loop)

            while not broadcast_queue.empty():
                broadcast_queue.get()

            asyncio.run_coroutine_threadsafe(_stop_loop(), self.loop)

        self.__broadcast_thread = threading.Thread(target=_schedule_job)
        self.__broadcast_thread.start()

    def _callback_connection_lost_callback(self, connection: RobustConnection):
        util.exit_and_msg("MQ Connection lost.")

    def stop(self):
        self.__broadcast_queue.put((None, None))
        self.__is_running = False  # even if broadcast queue has some items, the loop will be stopped immediately.

    def cleanup(self):
        self.__broadcast_thread.join()
        self._task.cleanup()

    @staticmethod
    def main(channel_name: str, amqp_target: str, amqp_key: str, peer_target: str,
             tx_versioner: TransactionVersioner, broadcast_queue: mp.Queue, properties: ModuleProcessProperties=None):
        if properties is not None:
            ModuleProcess.load_properties(properties, "txcreator")

        logging.info(f"Channel TX Creator start")

        broadcast_queue.cancel_join_thread()

        queue_name = conf.CHANNEL_TX_CREATOR_QUEUE_NAME_FORMAT.format(channel_name=channel_name, amqp_key=amqp_key)
        service = ChannelTxCreatorInnerService(broadcast_queue,
                                               amqp_target,
                                               queue_name,
                                               conf.AMQP_USERNAME,
                                               conf.AMQP_PASSWORD,
                                               channel_name=channel_name,
                                               peer_target=peer_target,
                                               tx_versioner=tx_versioner)

        def _on_signal(signal_num):
            logging.error(f"Channel TX Creator has been received signal({repr(signal_num)})")
            service.stop()

        service.loop.add_signal_handler(signal.SIGTERM, _on_signal, signal.SIGTERM)
        service.loop.add_signal_handler(signal.SIGINT, _on_signal, signal.SIGINT)

        service.serve(connection_attempts=conf.AMQP_CONNECTION_ATTEMPTS,
                      retry_delay=conf.AMQP_RETRY_DELAY, exclusive=True)
        logging.info("ChannelTxCreatorInnerService: started")
        service.serve_all()

        service.cleanup()
        service.loop.close()
        logging.info("ChannelTxCreatorInnerService: stopped")


class ChannelTxCreatorInnerStub(MessageQueueStub[ChannelTxCreatorInnerTask]):
    TaskType = ChannelTxCreatorInnerTask

    def _callback_connection_lost_callback(self, connection: RobustConnection):
        util.exit_and_msg("MQ Connection lost.")


class ChannelTxReceiverInnerTask:
    def __init__(self, tx_versioner: TransactionVersioner, tx_queue: mp.Queue):
        self.__nid: int = None
        self.__tx_versioner = tx_versioner
        self.__tx_queue = tx_queue

    @message_queue_task
    async def update_properties(self, properties: dict):
        try:
            self.__nid = properties['nid']
        except KeyError:
            pass

    @message_queue_task(type_=MessageQueueType.Worker)
    def add_tx_list(self, request) -> tuple:
        if self.__nid is None:
            response_code = message_code.Response.fail
            message = "Node initialization is not completed."
            return response_code, message

        tx_list = []
        for tx_item in request.tx_list:
            tx_json = json.loads(tx_item.tx_json)

            tx_version, tx_type = self.__tx_versioner.get_version(tx_json)

            ts = TransactionSerializer.new(tx_version, tx_type, self.__tx_versioner)
            tx = ts.from_(tx_json)

            tv = TransactionVerifier.new(tx_version, tx_type, self.__tx_versioner)
            tv.pre_verify(tx, nid=self.__nid)

            tx.size(self.__tx_versioner)

            tx_list.append(tx)

        tx_len = len(tx_list)
        if tx_len == 0:
            response_code = message_code.Response.fail
            message = "fail tx validate while AddTxList"
        else:
            self.__tx_queue.put(tx_list)
            response_code = message_code.Response.success
            message = f"success ({len(tx_list)})/({len(request.tx_list)})"

        return response_code, message


class ChannelTxReceiverInnerService(MessageQueueService[ChannelTxReceiverInnerTask]):
    TaskType = ChannelTxReceiverInnerTask

    def __init__(self, amqp_target, route_key, username=None, password=None, **task_kwargs):
        super().__init__(amqp_target, route_key, username, password, **task_kwargs)

    def _callback_connection_lost_callback(self, connection: RobustConnection):
        util.exit_and_msg("MQ Connection lost.")

    @staticmethod
    def main(channel_name: str, amqp_target: str, amqp_key: str,
             tx_versioner: TransactionVersioner, tx_queue: mp.Queue, properties: ModuleProcessProperties=None):
        if properties is not None:
            ModuleProcess.load_properties(properties, "txreceiver")

        logging.info(f"Channel TX Receiver start")

        tx_queue.cancel_join_thread()

        queue_name = conf.CHANNEL_TX_RECEIVER_QUEUE_NAME_FORMAT.format(channel_name=channel_name, amqp_key=amqp_key)
        service = ChannelTxReceiverInnerService(amqp_target, queue_name,
                                                conf.AMQP_USERNAME, conf.AMQP_PASSWORD,
                                                tx_versioner=tx_versioner, tx_queue=tx_queue)

        async def _stop_loop():
            service.loop.stop()

        def _on_signal(signal_num):
            logging.error(f"Channel TX Receiver has been received signal({repr(signal_num)})")
            asyncio.run_coroutine_threadsafe(_stop_loop(), service.loop)

        service.loop.add_signal_handler(signal.SIGTERM, _on_signal, signal.SIGTERM)
        service.loop.add_signal_handler(signal.SIGINT, _on_signal, signal.SIGINT)

        service.serve(connection_attempts=conf.AMQP_CONNECTION_ATTEMPTS,
                      retry_delay=conf.AMQP_RETRY_DELAY, exclusive=True)
        logging.info("ChannelTxReceiverInnerService: started")
        service.serve_all()

        service.loop.close()

        logging.info("ChannelTxReceiverInnerService: stopped")


class ChannelTxReceiverInnerStub(MessageQueueStub[ChannelTxReceiverInnerTask]):
    TaskType = ChannelTxReceiverInnerTask

    def _callback_connection_lost_callback(self, connection: RobustConnection):
        util.exit_and_msg("MQ Connection lost.")


class _ChannelTxCreatorProcess(ModuleProcess):
    def __init__(self, tx_versioner: TransactionVersioner, broadcast_scheduler: BroadcastScheduler,
                 crash_callback_in_join_thread):
        super().__init__()

        self.__broadcast_queue = self.Queue()
        self.__broadcast_queue.cancel_join_thread()

        args = (ChannelProperty().name,
                StubCollection().amqp_target,
                StubCollection().amqp_key,
                ChannelProperty().peer_target,
                tx_versioner,
                self.__broadcast_queue)
        super().start(target=ChannelTxCreatorInnerService.main,
                      args=args,
                      crash_callback_in_join_thread=crash_callback_in_join_thread)

        self.__broadcast_scheduler = broadcast_scheduler
        commands = (BroadcastCommand.UPDATE_AUDIENCE,)
        broadcast_scheduler.add_schedule_listener(self.__broadcast_callback, commands=commands)

    def start(self, target, args=(), crash_callback_in_join_thread=None):
        raise AttributeError("Doesn't support this function")

    def join(self):
        self.__broadcast_scheduler.remove_schedule_listener(self.__broadcast_callback)
        super().join()
        self.__broadcast_queue: mp.Queue = None

    def __broadcast_callback(self, command, params):
        self.__broadcast_queue.put((command, params))


class _ChannelTxReceiverProcess(ModuleProcess):
    def __init__(self, tx_versioner: TransactionVersioner, add_tx_list_callback, loop, crash_callback_in_join_thread):
        super().__init__()

        self.__is_running = True
        self.__tx_queue = self.Queue()
        self.__tx_queue.cancel_join_thread()

        async def _add_tx_list(tx_list):
            add_tx_list_callback(tx_list)

        def _receive_tx_list(tx_queue):
            while True:
                tx_list = tx_queue.get()
                if not self.__is_running or tx_list is None:
                    break
                asyncio.run_coroutine_threadsafe(_add_tx_list(tx_list), loop)

            while not tx_queue.empty():
                tx_queue.get()

        self.__receive_thread = threading.Thread(target=_receive_tx_list, args=(self.__tx_queue,))
        self.__receive_thread.start()

        args = (ChannelProperty().name,
                StubCollection().amqp_target,
                StubCollection().amqp_key,
                tx_versioner,
                self.__tx_queue)
        super().start(target=ChannelTxReceiverInnerService.main,
                      args=args,
                      crash_callback_in_join_thread=crash_callback_in_join_thread)

    def start(self, target, args=(), crash_callback_in_join_thread=None):
        raise AttributeError("Doesn't support this function")

    def join(self):
        super().join()
        self.__tx_queue.put(None)
        self.__is_running = False  # even if tx queue has some items, the loop will be stopped immediately.
        self.__receive_thread.join()
        self.__tx_queue: mp.Queue = None
        self.__receive_thread: threading.Thread = None


class ChannelInnerTask:
    def __init__(self, channel_service: 'ChannelService'):
        self._channel_service = channel_service
        self._block_manager = None
        self._blockchain = None

        # Citizen
        CitizenInfo = namedtuple("CitizenInfo", "peer_id target connected_time")
        self._CitizenInfo = CitizenInfo
        self._citizens: Dict[str, CitizenInfo] = dict()
        self._citizen_condition_new_block: Condition = None
        self._citizen_condition_unregister: Condition = None
        self._event_system: EventSystem = None

        self.__sub_processes = []
        self.__loop_for_sub_services = None

    def init_sub_service(self, loop):
        if len(self.__sub_processes) > 0:
            raise RuntimeError("Channel sub services have already been initialized")

        if loop is None:
            raise RuntimeError("Channel sub services need a loop")
        self.__loop_for_sub_services = loop

        self._block_manager = self._channel_service.block_manager
        self._blockchain = self._channel_service.block_manager.blockchain

        tx_versioner = self._blockchain.tx_versioner

        def crash_callback_in_join_thread(process: ModuleProcess):
            asyncio.run_coroutine_threadsafe(self.__handle_crash_sub_services(process), loop)

        broadcast_scheduler = self._channel_service.broadcast_scheduler
        tx_creator_process = _ChannelTxCreatorProcess(tx_versioner,
                                                      broadcast_scheduler,
                                                      crash_callback_in_join_thread)
        self.__sub_processes.append(tx_creator_process)
        logging.info(f"Channel({ChannelProperty().name}) TX Creator: initialized")

        tx_receiver_process = _ChannelTxReceiverProcess(tx_versioner,
                                                        self.__add_tx_list,
                                                        loop,
                                                        crash_callback_in_join_thread)
        self.__sub_processes.append(tx_receiver_process)
        logging.info(f"Channel({ChannelProperty().name}) TX Receiver: initialized")

    def update_sub_services_properties(self, **properties):
        logging.info(f"properties {properties}")
        stub = StubCollection().channel_tx_creator_stubs[ChannelProperty().name]
        asyncio.run_coroutine_threadsafe(stub.async_task().update_properties(properties), self.__loop_for_sub_services)

        stub = StubCollection().channel_tx_receiver_stubs[ChannelProperty().name]
        asyncio.run_coroutine_threadsafe(stub.async_task().update_properties(properties), self.__loop_for_sub_services)

    def cleanup_sub_services(self):
        for process in self.__sub_processes:
            process.terminate()
            process.join()
        self.__sub_processes = []

    async def __handle_crash_sub_services(self, process: ModuleProcess):
        try:
            self.__sub_processes.remove(process)
            process.join()

            logging.critical(f"Channel sub process crash occurred. process={process}")

            async def _close():
                if not self.__loop_for_sub_services.is_closed():
                    self._channel_service.close()

            asyncio.ensure_future(_close(), loop=self.__loop_for_sub_services)
        except ValueError:
            # Call this function by cleanup
            pass

    def __add_tx_list(self, tx_list):
        for tx in tx_list:
            if tx.hash.hex() in self._block_manager.get_tx_queue():
                util.logger.debug(f"tx hash {tx.hash.hex_0x()} already exists in transaction queue.")
                continue
            if self._blockchain.find_tx_by_key(tx.hash.hex()):
                util.logger.debug(f"tx hash {tx.hash.hex_0x()} already exists in blockchain.")
                continue

            self._block_manager.add_tx_obj(tx)

        if not conf.ALLOW_MAKE_EMPTY_BLOCK:
            self._channel_service.start_leader_complain_timer_if_tx_exists()

    @message_queue_task
    async def hello(self):
        return 'channel_hello'

    @message_queue_task
    async def announce_new_block(self, subscriber_block_height: int, subscriber_id: str):
        while True:
            my_block_height = self._blockchain.block_height
            if subscriber_block_height > my_block_height:
                logging.warning(f"subscriber's height({subscriber_block_height}) is higher "
                                f"than this node's height({my_block_height}).")
                self._channel_service.inner_service.notify_unregister()
                error_msg = {"error": "Invalid block height from citizen."}
                return json.dumps(error_msg), b''
            elif subscriber_block_height == my_block_height:
                async with self._citizen_condition_new_block:
                    await self._citizen_condition_new_block.wait()

            new_block_height = subscriber_block_height + 1
            new_block = self._blockchain.find_block_by_height(new_block_height)

            if new_block is None:
                logging.warning(f"Cannot find block height({new_block_height})")
                # To prevent excessive occupancy of the CPU in an infinite loop
                await asyncio.sleep(2 * conf.INTERVAL_BLOCKGENERATION)
                continue

            confirm_info: bytes = self._blockchain.find_confirm_info_by_hash(new_block.header.hash)

            logging.debug(f"announce_new_block: height({new_block.header.height}), to: {subscriber_id}")
            bs = BlockSerializer.new(new_block.header.version, self._blockchain.tx_versioner)
            return json.dumps(bs.serialize(new_block)), confirm_info

    @message_queue_task
    async def register_citizen(self, peer_id, target, connected_time):
        register_condition = (len(self._citizens) < conf.SUBSCRIBE_LIMIT
                              and (peer_id not in self._citizens)
                              and not (conf.SAFE_BLOCK_BROADCAST and
                                       self._channel_service.state_machine.state == 'BlockGenerate'))
        if register_condition:
            new_citizen = self._CitizenInfo(peer_id, target, connected_time)
            self._citizens[peer_id] = new_citizen
            logging.info(f"register new citizen: {new_citizen}")
            logging.debug(f"remaining all citizens: {self._citizens}")

        return register_condition

    @message_queue_task
    async def unregister_citizen(self, peer_id):
        try:
            logging.info(f"unregister citizen: {peer_id}")
            del self._citizens[peer_id]
            logging.debug(f"remaining all citizens: {self._citizens}")
        except KeyError as e:
            logging.warning(f"already unregistered citizen({peer_id})")

    @message_queue_task
    async def wait_for_unregister_signal(self, subscriber_id: str):
        async with self._citizen_condition_unregister:
            await self._citizen_condition_unregister.wait()

        logging.debug(f"citizen({subscriber_id}) will be unregistered from this node")
        return True

    @message_queue_task
    async def is_citizen_registered(self, peer_id) -> bool:
        return peer_id in self._citizens

    @message_queue_task
    async def get_citizens(self) -> List[Dict[str, str]]:
        return [{"id": ctz.peer_id, "target": ctz.target, "connected_time": ctz.connected_time}
                for ctz in self._citizens.values()]

    @message_queue_task
    async def get_reps_by_hash(self, reps_hash: str) -> List[Dict[str, str]]:
        new_reps_hash = Hash32.fromhex(reps_hash)
        preps = self._blockchain.find_preps_by_roothash(new_reps_hash)
        return preps

    @message_queue_task(priority=255)
    async def get_status(self):
        status_data = dict()
        status_data["made_block_count"] = self._blockchain.my_made_block_count
        status_data["leader_made_block_count"] = self._blockchain.leader_made_block_count

        block_height = 0
        unconfirmed_block_height = None
        peer_count = -1
        last_block = self._blockchain.last_block
        last_unconfirmed_block = self._blockchain.last_unconfirmed_block

        if last_block:
            block_height = last_block.header.height
            peer_count = len(self._blockchain.find_preps_addresses_by_header(last_block.header))

        if last_unconfirmed_block:
            unconfirmed_block_height = last_unconfirmed_block.header.height

        status_data["nid"] = ChannelProperty().nid
        status_data["status"] = self._block_manager.service_status
        status_data["state"] = self._channel_service.state_machine.state
        status_data["service_available"]: bool = \
            (status_data["state"] in self._channel_service.state_machine.service_available_states)
        status_data["peer_type"] = \
            str(1 if self._channel_service.state_machine.state == "BlockGenerate" else 0)
        status_data["audience_count"] = "0"
        status_data["consensus"] = str(conf.CONSENSUS_ALGORITHM.name)
        status_data["peer_id"] = str(ChannelProperty().peer_id)
        status_data["block_height"] = block_height
        status_data["round"] = self._block_manager.epoch.round if self._block_manager.epoch else -1
        status_data["epoch_height"] = self._block_manager.epoch.height if self._block_manager.epoch else -1
        status_data["unconfirmed_block_height"] = unconfirmed_block_height or -1
        status_data["total_tx"] = self._block_manager.get_total_tx()
        status_data["unconfirmed_tx"] = self._block_manager.get_count_of_unconfirmed_tx()
        status_data["peer_target"] = ChannelProperty().peer_target
        status_data["leader_complaint"] = 1
        status_data["peer_count"] = peer_count
        status_data["leader"] = self._block_manager.epoch.leader_id if self._block_manager.epoch else ""
        status_data["epoch_leader"] = self._block_manager.epoch.leader_id if self._block_manager.epoch else ""
        status_data["versions"] = conf.ICON_VERSIONS

        return status_data

    @message_queue_task
    def get_tx_info(self, tx_hash):
        tx = self._block_manager.get_tx_queue().get(tx_hash, None)
        if tx:
            tx_serializer = TransactionSerializer.new(tx.version, tx.type(), self._blockchain.tx_versioner)
            tx_origin = tx_serializer.to_origin_data(tx)

            logging.info(f"get_tx_info pending : tx_hash({tx_hash})")
            tx_info = dict()
            tx_info["transaction"] = tx_origin
            tx_info["tx_index"] = None
            tx_info["block_height"] = None
            tx_info["block_hash"] = None
            return message_code.Response.success, tx_info
        else:
            try:
                return message_code.Response.success, self._block_manager.get_tx_info(tx_hash)
            except KeyError as e:
                logging.error(f"get_tx_info error : tx_hash({tx_hash}) not found error({e})")
                response_code = message_code.Response.fail_invalid_key_error
                return response_code, None

    @message_queue_task(type_=MessageQueueType.Worker)
    async def announce_unconfirmed_block(self, block_dumped, round_: int) -> None:
        try:
            unconfirmed_block = self._blockchain.block_loads(block_dumped)
        except BlockError as e:
            traceback.print_exc()
            logging.error(f"announce_unconfirmed_block: {e}")
            return

        util.logger.debug(
            f"announce_unconfirmed_block \n"
            f"peer_id({unconfirmed_block.header.peer_id.hex()})\n"
            f"height({unconfirmed_block.header.height})\n"
            f"round({round_})\n"
            f"hash({unconfirmed_block.header.hash.hex()})")

        if self._channel_service.state_machine.state not in \
                ("Vote", "Watch", "LeaderComplain", "BlockGenerate"):
            util.logger.debug(f"Can't add unconfirmed block in state({self._channel_service.state_machine.state}).")
            return

        last_block = self._blockchain.last_block
        if last_block is None:
            util.logger.debug("BlockChain has not been initialized yet.")
            return

        try:
            self._block_manager.verify_confirm_info(unconfirmed_block)
        except ConfirmInfoInvalid as e:
            util.logger.warning(f"ConfirmInfoInvalid {e}")
        except ConfirmInfoInvalidNeedBlockSync as e:
            util.logger.debug(f"ConfirmInfoInvalidNeedBlockSync {e}")
            if self._channel_service.state_machine.state == "BlockGenerate" and (
                    self._block_manager.consensus_algorithm and self._block_manager.consensus_algorithm.is_running):
                self._block_manager.consensus_algorithm.stop()
            else:
                self._channel_service.state_machine.block_sync()
        except ConfirmInfoInvalidAddedBlock as e:
            util.logger.warning(f"ConfirmInfoInvalidAddedBlock {e}")
        except NotReadyToConfirmInfo as e:
            util.logger.warning(f"NotReadyToConfirmInfo {e}")
        else:
            self._channel_service.state_machine.vote(unconfirmed_block=unconfirmed_block, round_=round_)

    @message_queue_task
    def block_sync(self, block_hash, block_height):
        response_code = None
        block: Block = None
        if block_hash != "":
            block = self._blockchain.find_block_by_hash(block_hash)
        elif block_height != -1:
            block = self._blockchain.find_block_by_height(block_height)
        else:
            response_code = message_code.Response.fail_not_enough_data

        if self._blockchain.last_unconfirmed_block is None:
            unconfirmed_block_height = -1
        else:
            unconfirmed_block_height = self._blockchain.last_unconfirmed_block.header.height

        if block is None:
            if response_code is None:
                response_code = message_code.Response.fail_wrong_block_hash
            return response_code, -1, self._blockchain.block_height, unconfirmed_block_height, None, None

        confirm_info = None
        if 0 < block.header.height <= self._blockchain.block_height:
            confirm_info = self._blockchain.find_confirm_info_by_hash(block.header.hash)
            if not confirm_info and parse_version(block.header.version) >= parse_version("0.3"):
                response_code = message_code.Response.fail_no_confirm_info
                return response_code, -1, self._blockchain.block_height, unconfirmed_block_height, None, None

        return (message_code.Response.success, block.header.height, self._blockchain.block_height,
                unconfirmed_block_height, confirm_info, self._blockchain.block_dumps(block))

    @message_queue_task(type_=MessageQueueType.Worker)
    def vote_unconfirmed_block(self, vote_dumped: str) -> None:
        try:
            vote_serialized = json.loads(vote_dumped)
        except json.decoder.JSONDecodeError:
            util.logger.warning(f"This vote({vote_dumped}) may be from old version.")
        else:
            height: str = vote_serialized.get("blockHeight")  # FIXME
            version = self._blockchain.block_versioner.get_version(int(height, 16))
            if parse_version(version) == parse_version("1.0"):
                from loopchain.blockchain.votes import v1_0
                vote = v1_0.BlockVote._deserialize(**vote_serialized)
                vote_round = vote.round_num
                vote_block_hash = vote.id
                voter = vote.voter_id
            else:
                vote = Vote.get_block_vote_class(version).deserialize(vote_serialized)
                vote_round = vote.round
                vote_block_hash = vote.block_hash
                voter = vote.rep.hex_hx()
            util.logger.debug(
                f"Peer vote to: {vote.block_height}({vote_round}) {vote_block_hash} from {voter}"
            )
            if self._event_system:
                util.logger.notice(f'loopchain 3.x has event_system!')
                e = ReceiveVoteEvent(vote)
                self._event_system.simulator.raise_event(e)
            else:
                util.logger.notice(f'loopchain 2.x has no event_system!')
                self._block_manager.candidate_blocks.add_vote(vote)

                if self._channel_service.state_machine.state == "BlockGenerate" and \
                        self._block_manager.consensus_algorithm:
                    self._block_manager.consensus_algorithm.vote(vote)

    @message_queue_task(type_=MessageQueueType.Worker)
    async def complain_leader(self, vote_dumped: str) -> None:
        vote_serialized = json.loads(vote_dumped)
        version = self._blockchain.block_versioner.get_version(int(vote_serialized["blockHeight"], 16))
        vote = Vote.get_leader_vote_class(version).deserialize(vote_serialized)
        self._block_manager.add_complain(vote)

    @message_queue_task
    def get_invoke_result(self, tx_hash):
        try:
            invoke_result = self._block_manager.get_invoke_result(tx_hash)
            invoke_result_str = json.dumps(invoke_result)
            response_code = message_code.Response.success
            logging.debug('invoke_result : ' + invoke_result_str)

            if 'code' in invoke_result:
                if invoke_result['code'] == ScoreResponse.NOT_EXIST:
                    logging.debug(f"get invoke result NOT_EXIST tx_hash({tx_hash})")
                    response_code = message_code.Response.fail_invalid_key_error
                elif invoke_result['code'] == ScoreResponse.NOT_INVOKED:
                    logging.info(f"get invoke result NOT_INVOKED tx_hash({tx_hash})")
                    response_code = message_code.Response.fail_tx_not_invoked

            return response_code, invoke_result_str
        except BaseException as e:
            logging.error(f"get invoke result error : {e}")

            return message_code.Response.fail, None

    @message_queue_task
    async def get_block_v2(self, block_height, block_hash) -> Tuple[int, str, str]:
        # This is a temporary function for v2 support of exchanges.
        block, block_hash, _, fail_response_code = await self.__get_block(block_hash, block_height)
        if fail_response_code:
            return fail_response_code, block_hash, json.dumps({})

        tx_versioner = self._blockchain.tx_versioner
        bs = BlockSerializer.new(block.header.version, tx_versioner)
        block_data_dict = bs.serialize(block)

        if block.header.height == 0:
            return message_code.Response.success, block_hash, json.dumps(block_data_dict)

        confirmed_tx_list_without_fail = []
        for tx in block.body.transactions.values():
            invoke_result = self._block_manager.get_invoke_result(tx.hash)

            if 'failure' in invoke_result:
                continue

            ts = TransactionSerializer.new(tx.version, tx.type(), tx_versioner)
            full_data = ts.to_full_data(tx)
            if tx.version == "0x3":
                step_used, step_price = int(invoke_result["stepUsed"], 16), int(invoke_result["stepPrice"], 16)
                full_data["fee"] = hex(step_used * step_price)

            confirmed_tx_list_without_fail.append(full_data)

        # Replace the existing confirmed_transactions with v2 ver.
        if block.header.version == "0.1a":
            block_data_dict["confirmed_transaction_list"] = confirmed_tx_list_without_fail
        else:
            block_data_dict["transactions"] = confirmed_tx_list_without_fail
        block_data_json = json.dumps(block_data_dict)

        if fail_response_code:
            return fail_response_code, block_hash, json.dumps({})

        return message_code.Response.success, block_hash, block_data_json

    @message_queue_task
    async def get_block(self, block_height, block_hash) -> Tuple[int, str, bytes, str]:
        block, block_hash, confirm_info, fail_response_code = await self.__get_block(block_hash, block_height)

        if fail_response_code:
            return fail_response_code, block_hash, b"", json.dumps({})

        tx_versioner = self._blockchain.tx_versioner
        bs = BlockSerializer.new(block.header.version, tx_versioner)
        block_dict = bs.serialize(block)
        return message_code.Response.success, block_hash, confirm_info, json.dumps(block_dict)

    async def __get_block(self, block_hash, block_height):
        if block_hash == "" and block_height == -1 and self._blockchain.last_block:
            block_hash = self._blockchain.last_block.header.hash.hex()

        block = None
        confirm_info = b''
        fail_response_code = None
        if block_hash:
            block = self._blockchain.find_block_by_hash(block_hash)
            if block is None:
                fail_response_code = message_code.Response.fail_wrong_block_hash
                confirm_info = bytes()
            else:
                confirm_info = self._blockchain.find_confirm_info_by_hash(Hash32.fromhex(block_hash, True))
        elif block_height != -1:
            block = self._blockchain.find_block_by_height(block_height)
            if block is None:
                fail_response_code = message_code.Response.fail_wrong_block_height
                confirm_info = bytes()
            else:
                confirm_info = self._blockchain.find_confirm_info_by_hash(block.header.hash)
        else:
            fail_response_code = message_code.Response.fail_wrong_block_hash

        return block, block_hash, bytes(confirm_info), fail_response_code

    @message_queue_task
    def get_tx_by_address(self, address, index):
        tx_list, next_index = self._blockchain.get_tx_list_by_address(address=address, index=index)

        return tx_list, next_index

    @message_queue_task
    async def get_tx_proof(self, tx_hash: str) -> Union[list, dict]:
        try:
            proof = self._blockchain.get_transaction_proof(Hash32.fromhex(tx_hash))
        except Exception as e:
            return make_error_response(JsonError.INVALID_PARAMS, str(e))

        try:
            return make_proof_serializable(proof)
        except Exception as e:
            return make_error_response(JsonError.INTERNAL_ERROR, str(e))

    @message_queue_task
    async def prove_tx(self, tx_hash: str, proof: list) -> Union[str, dict]:
        try:
            proof = make_proof_deserializable(proof)
        except Exception as e:
            return make_error_response(JsonError.INTERNAL_ERROR, str(e))

        try:
            return "0x1" if self._blockchain.prove_transaction(Hash32.fromhex(tx_hash), proof) else "0x0"
        except Exception as e:
            return make_error_response(JsonError.INVALID_PARAMS, str(e))

    @message_queue_task
    async def get_receipt_proof(self, tx_hash: str) -> Union[list, dict]:
        try:
            proof = self._blockchain.get_receipt_proof(Hash32.fromhex(tx_hash))
        except Exception as e:
            return make_error_response(JsonError.INVALID_PARAMS, str(e))

        try:
            return make_proof_serializable(proof)
        except Exception as e:
            return make_error_response(JsonError.INTERNAL_ERROR, str(e))

    @message_queue_task
    async def prove_receipt(self, tx_hash: str, proof: list) -> Union[str, dict]:
        try:
            proof = make_proof_deserializable(proof)
        except Exception as e:
            return make_error_response(JsonError.INTERNAL_ERROR, str(e))

        try:
            return "0x1" if self._blockchain.prove_receipt(Hash32.fromhex(tx_hash), proof) else "0x0"
        except Exception as e:
            return make_error_response(JsonError.INVALID_PARAMS, str(e))

    @message_queue_task
    def reset_timer(self, key):
        self._channel_service.timer_service.reset_timer(key)

    @message_queue_task(type_=MessageQueueType.Worker)
    def stop(self, message):
        logging.info(f"channel_inner_service:stop message({message})")
        self._channel_service.close()


class ChannelInnerService(MessageQueueService[ChannelInnerTask]):
    TaskType = ChannelInnerTask

    def __init__(self, event_system, amqp_target, route_key, username=None, password=None, **task_kwargs):
        super().__init__(amqp_target, route_key, username, password, **task_kwargs)
        self._task._citizen_condition_new_block = Condition(loop=self.loop)
        self._task._citizen_condition_unregister = Condition(loop=self.loop)
        self._task._event_system = event_system

    def _callback_connection_lost_callback(self, connection: RobustConnection):
        util.exit_and_msg("MQ Connection lost.")

    def notify_new_block(self):

        async def _notify_new_block():
            condition = self._task._citizen_condition_new_block
            async with condition:
                condition.notify_all()

        asyncio.run_coroutine_threadsafe(_notify_new_block(), self.loop)

    def notify_unregister(self):

        async def _notify_unregister():
            condition = self._task._citizen_condition_unregister
            async with condition:
                condition.notify_all()
        asyncio.run_coroutine_threadsafe(_notify_unregister(), self.loop)

    def init_sub_services(self):
        if self.loop != asyncio.get_event_loop():
            raise Exception("Must call this function in thread of self.loop")
        self._task.init_sub_service(self.loop)

    def update_sub_services_properties(self, **properties):
        self._task.update_sub_services_properties(**properties)

    def cleanup(self):
        if self.loop != asyncio.get_event_loop():
            raise Exception("Must call this function in thread of self.loop")
        self._task.cleanup_sub_services()
        logging.info("Cleanup ChannelInnerService.")


class ChannelInnerStub(MessageQueueStub[ChannelInnerTask]):
    TaskType = ChannelInnerTask

    def _callback_connection_lost_callback(self, connection: RobustConnection):
        util.exit_and_msg("MQ Connection lost.")


def make_proof_serializable(proof: list):
    proof_serializable = []
    for item in proof:
        try:
            left = Hash32(item["left"])
            proof_serializable.append({"left": left.hex_0x()})
        except KeyError:
            right = Hash32(item["right"])
            proof_serializable.append({"right": right.hex_0x()})
    return proof_serializable


def make_proof_deserializable(proof: list):
    proof_deserializable = []
    for item in proof:
        try:
            left: str = item["left"]
            proof_deserializable.append({"left": Hash32.fromhex(left)})
        except KeyError:
            right: str = item["right"]
            proof_deserializable.append({"right": Hash32.fromhex(right)})
    return proof_deserializable


def make_error_response(code: int, message: str):
    return {
        "error": {
            "code": code,
            "message": message
        }
    }
