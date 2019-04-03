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

import ast
import json
import multiprocessing as mp
import re
import signal
from asyncio import Condition
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Union

from earlgrey import *

from loopchain import configure as conf
from loopchain import utils as util
from loopchain.rest_server.json_rpc import JsonError
from loopchain.baseservice import BroadcastCommand, BroadcastScheduler, BroadcastSchedulerFactory, ScoreResponse
from loopchain.baseservice import PeerInfo
from loopchain.baseservice.module_process import ModuleProcess, ModuleProcessProperties
from loopchain.blockchain import (Transaction, TransactionSerializer, TransactionVerifier, TransactionVersioner,
                                  Block, BlockBuilder, BlockSerializer, blocks, Hash32)
from loopchain.blockchain.exception import *
from loopchain.channel.channel_property import ChannelProperty
from loopchain.protos import loopchain_pb2, message_code
from loopchain.utils.message_queue import StubCollection

if TYPE_CHECKING:
    from loopchain.channel.channel_service import ChannelService


class ChannelTxCreatorInnerTask:
    def __init__(self, channel_name: str, peer_target: str, tx_versioner: TransactionVersioner):
        self.__channel_name = channel_name
        self.__tx_versioner = tx_versioner

        scheduler = BroadcastSchedulerFactory.new(channel=channel_name,
                                                  self_target=peer_target,
                                                  is_multiprocessing=True)
        scheduler.start()

        self.__broadcast_scheduler = scheduler

        scheduler.schedule_job(BroadcastCommand.SUBSCRIBE, peer_target,
                               block=True, block_timeout=conf.TIMEOUT_FOR_FUTURE)

    def __pre_validate(self, tx: Transaction):
        if not util.is_in_time_boundary(tx.timestamp, conf.ALLOW_TIMESTAMP_BOUNDARY_SECOND):
            raise TransactionInvalidOutOfTimeBound(tx.hash.hex(), tx.timestamp, util.get_now_time_stamp())

    def cleanup(self):
        self.__broadcast_scheduler.stop()
        self.__broadcast_scheduler.wait()
        self.__broadcast_scheduler: BroadcastScheduler = None

    @message_queue_task
    async def create_icx_tx(self, kwargs: dict):
        result_code = None
        exception = None
        tx = None

        try:
            tx_version = self.__tx_versioner.get_version(kwargs)

            ts = TransactionSerializer.new(tx_version, self.__tx_versioner)
            tx = ts.from_(kwargs)

            tv = TransactionVerifier.new(tx_version, self.__tx_versioner)
            tv.verify(tx)

            self.__pre_validate(tx)

            logging.debug(f"create icx input : {kwargs}")

            self.__broadcast_scheduler.schedule_job(BroadcastCommand.CREATE_TX, (tx, self.__tx_versioner))
            return message_code.Response.success, tx.hash.hex()

        except TransactionInvalidError as e:
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
                return result_code, None

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
            logging.error(f"Channel TX Creator has been received signal({signal_num})")
            service.stop()

        service.loop.add_signal_handler(signal.SIGTERM, _on_signal, (signal.SIGTERM,))
        service.loop.add_signal_handler(signal.SIGINT, _on_signal, (signal.SIGINT,))

        service.serve(connection_attempts=conf.AMQP_CONNECTION_ATTEMPS,
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
        self.__tx_versioner = tx_versioner
        self.__tx_queue = tx_queue

    @message_queue_task(type_=MessageQueueType.Worker)
    def add_tx_list(self, request) -> tuple:
        tx_list = []
        for tx_item in request.tx_list:
            tx_json = json.loads(tx_item.tx_json)

            tx_version = self.__tx_versioner.get_version(tx_json)

            ts = TransactionSerializer.new(tx_version, self.__tx_versioner)
            tx = ts.from_(tx_json)

            tv = TransactionVerifier.new(tx_version, self.__tx_versioner)
            tv.verify(tx)

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
    def main(channel_name: str, amqp_target: str, amqp_key: str, tx_versioner: TransactionVersioner, tx_queue: mp.Queue,
             properties: ModuleProcessProperties=None):
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
            logging.error(f"Channel TX Receiver has been received signal({signal_num})")
            asyncio.run_coroutine_threadsafe(_stop_loop(), service.loop)

        service.loop.add_signal_handler(signal.SIGTERM, _on_signal, (signal.SIGTERM,))
        service.loop.add_signal_handler(signal.SIGINT, _on_signal, (signal.SIGINT,))

        service.serve(connection_attempts=conf.AMQP_CONNECTION_ATTEMPS,
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
        commands = (BroadcastCommand.SUBSCRIBE, BroadcastCommand.UNSUBSCRIBE)
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
        self._thread_pool = ThreadPoolExecutor(1, "ChannelInnerThread")

        # Citizen
        self._citizen_condition_new_block: Condition = None
        self._citizen_set = set()

        self.__sub_processes = []
        self.__loop_for_sub_services = None

    def init_sub_service(self, loop):
        if len(self.__sub_processes) > 0:
            raise RuntimeError("Channel sub services have already been initialized")

        if loop is None:
            raise RuntimeError("Channel sub services need a loop")
        self.__loop_for_sub_services = loop

        tx_versioner = self._channel_service.block_manager.get_blockchain().tx_versioner

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
        block_manager = self._channel_service.block_manager
        blockchain = block_manager.get_blockchain()

        for tx in tx_list:
            if blockchain.find_tx_by_key(tx.hash.hex()):
                util.logger.warning(f"tx({tx})\n"
                                    f"hash {tx.hash.hex()} already exists in blockchain.")
                continue

            block_manager.add_tx_obj(tx)
            util.apm_event(ChannelProperty().peer_id, {
                'event_type': 'AddTx',
                'peer_id': ChannelProperty().peer_id,
                'peer_name': conf.PEER_NAME,
                'channel_name': ChannelProperty().name,
                'data': {'tx_hash': tx.hash.hex()}})

        self._channel_service.start_leader_complain_timer_if_tx_exists()

    @message_queue_task
    async def hello(self):
        return 'channel_hello'

    @message_queue_task
    async def announce_new_block(self, subscriber_block_height: int):
        blockchain = self._channel_service.block_manager.get_blockchain()

        while True:
            my_block_height = blockchain.block_height
            if subscriber_block_height > my_block_height:
                message = {'error': "Announced block height is lower than subscriber's."}
                return json.dumps(message)

            if subscriber_block_height == my_block_height:
                async with self._citizen_condition_new_block:
                    await self._citizen_condition_new_block.wait()

            new_block_height = subscriber_block_height + 1
            new_block = blockchain.find_block_by_height(new_block_height)

            if new_block is None:
                logging.warning(f"Cannot find block height({new_block_height})")
                await asyncio.sleep(0.5)  # To prevent excessive occupancy of the CPU in an infinite loop
                continue

            logging.debug(f"announce_new_block: height({new_block.header.height}), hash({new_block.header.hash}), "
                          f"target: {self._citizen_set}")
            bs = BlockSerializer.new(new_block.header.version, blockchain.tx_versioner)
            return json.dumps(bs.serialize(new_block))

    @message_queue_task
    async def register_subscriber(self, peer_id):
        if len(self._citizen_set) >= conf.SUBSCRIBE_LIMIT:
            return False
        else:
            self._citizen_set.add(peer_id)
            logging.info(f"register new subscriber: {peer_id}")
            logging.debug(f"remaining all subscribers: {self._citizen_set}")
            return True

    @message_queue_task
    async def unregister_subscriber(self, peer_id):
        logging.info(f"unregister subscriber: {peer_id}")
        self._citizen_set.remove(peer_id)
        logging.debug(f"remaining all subscribers: {self._citizen_set}")

    @message_queue_task
    async def is_registered_subscriber(self, peer_id):
        return peer_id in self._citizen_set

    @message_queue_task
    def get_peer_list(self):
        peer_manager = self._channel_service.peer_manager
        return str(peer_manager.peer_list[conf.ALL_GROUP_ID]), str(peer_manager.peer_list)

    @message_queue_task(type_=MessageQueueType.Worker)
    async def reset_leader(self, new_leader, block_height=0) -> None:
        await self._channel_service.reset_leader(new_leader, block_height)

    @message_queue_task(priority=255)
    async def get_status(self):
        status_data = dict()
        block_manager = self._channel_service.block_manager
        status_data["made_block_count"] = block_manager.made_block_count

        block_height = 0
        unconfirmed_block_height = None
        last_block = block_manager.get_blockchain().last_block
        last_unconfirmed_block = block_manager.get_blockchain().last_unconfirmed_block

        if last_block:
            block_height = last_block.header.height

        if last_unconfirmed_block:
            unconfirmed_block_height = last_unconfirmed_block.header.height

        status_data["status"] = block_manager.service_status
        status_data["state"] = self._channel_service.state_machine.state
        status_data["peer_type"] = str(1 if self._channel_service.state_machine.state == "BlockGenerate" else 0)
        status_data["audience_count"] = "0"
        status_data["consensus"] = str(conf.CONSENSUS_ALGORITHM.name)
        status_data["peer_id"] = str(ChannelProperty().peer_id)
        status_data["block_height"] = block_height
        status_data["unconfirmed_block_height"] = unconfirmed_block_height or -1
        status_data["total_tx"] = block_manager.get_total_tx()
        status_data["unconfirmed_tx"] = block_manager.get_count_of_unconfirmed_tx()
        status_data["peer_target"] = ChannelProperty().peer_target
        status_data["leader_complaint"] = 1
        status_data["peer_count"] = len(self._channel_service.peer_manager.peer_list[conf.ALL_GROUP_ID])
        status_data["leader"] = self._channel_service.peer_manager.get_leader_id(conf.ALL_GROUP_ID) or ""
        status_data["epoch_leader"] = \
            self._channel_service.block_manager.epoch.leader_id if self._channel_service.block_manager.epoch else ""

        return status_data

    @message_queue_task
    def create_tx(self, data):
        tx = Transaction()
        score_id = ""
        score_version = ""

        try:
            score_info = self._channel_service.score_info
            score_id = score_info[message_code.MetaParams.ScoreInfo.score_id]
            score_version = score_info[message_code.MetaParams.ScoreInfo.score_version]
        except KeyError as e:
            logging.debug(f"CreateTX : load score info fail\n"
                          f"cause : {e}")

        send_tx_type = self._channel_service.get_channel_option()["send_tx_type"]
        tx.init_meta(ChannelProperty().peer_id, score_id, score_version, ChannelProperty().name, send_tx_type)
        tx.put_data(data)
        tx.sign_hash(self._channel_service.peer_auth)

        self._channel_service.broadcast_scheduler.schedule_job(BroadcastCommand.CREATE_TX, tx)

        try:
            data_log = json.loads(data)
        except Exception as e:
            data_log = {'tx_hash': tx.tx_hash}

        util.apm_event(ChannelProperty().peer_id, {
            'event_type': 'CreateTx',
            'peer_id': ChannelProperty().peer_id,
            'peer_name': conf.PEER_NAME,
            'channel_name': ChannelProperty().name,
            'tx_hash': tx.tx_hash,
            'data': data_log})

        return tx.tx_hash

    @message_queue_task(type_=MessageQueueType.Worker)
    def add_tx(self, request) -> None:
        tx_json = request.tx_json

        tx_versioner = self._channel_service.block_manager.get_blockchain().tx_versioner
        tx_version = tx_versioner.get_version(tx_json)

        ts = TransactionSerializer.new(tx_version, tx_versioner)
        tx = ts.from_(tx_json)

        tv = TransactionVerifier.new(tx_version, tx_versioner)
        tv.verify(tx)

        if tx is not None:
            self._channel_service.block_manager.add_tx_obj(tx)
            util.apm_event(ChannelProperty().peer_id, {
                'event_type': 'AddTx',
                'peer_id': ChannelProperty().peer_id,
                'peer_name': conf.PEER_NAME,
                'channel_name': ChannelProperty().name,
                'data': {'tx_hash': tx.tx_hash}})

        self._channel_service.start_leader_complain_timer_if_tx_exists()

    @message_queue_task
    def get_tx(self, tx_hash):
        return self._channel_service.block_manager.get_tx(tx_hash)

    @message_queue_task
    def get_tx_info(self, tx_hash):
        tx = self._channel_service.block_manager.get_tx_queue().get(tx_hash, None)
        if tx:
            blockchain = self._channel_service.block_manager.get_blockchain()
            tx_serializer = TransactionSerializer.new(tx.version, blockchain.tx_versioner)
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
                return message_code.Response.success, self._channel_service.block_manager.get_tx_info(tx_hash)
            except KeyError as e:
                logging.error(f"get_tx_info error : tx_hash({tx_hash}) not found error({e})")
                response_code = message_code.Response.fail_invalid_key_error
                return response_code, None

    def __is_unconfirmed_block_by_complained_leader(self, unconfirmed_block: Block):
        last_unconfirmed_block = self._channel_service.block_manager.get_blockchain().last_unconfirmed_block
        if last_unconfirmed_block is None:
            return False
        elif self._channel_service.state_machine.state != "LeaderComplain":
            return False

        return last_unconfirmed_block.header.hash == unconfirmed_block.header.hash \
            and last_unconfirmed_block.header.height == unconfirmed_block.header.height \
            and self._channel_service.block_manager.epoch.leader_id == unconfirmed_block.header.peer_id.hex_hx()

    @message_queue_task(type_=MessageQueueType.Worker)
    async def announce_unconfirmed_block(self, block_dumped) -> None:
        try:
            unconfirmed_block = self._channel_service.block_manager.get_blockchain().block_loads(block_dumped)
        except BlockError as e:
            traceback.print_exc()
            logging.error(f"announce_unconfirmed_block: {e}")
            return

        logging.debug(f"#block \n"
                      f"peer_id({unconfirmed_block.header.peer_id.hex()})\n"
                      f"height({unconfirmed_block.header.height})\n"
                      f"hash({unconfirmed_block.header.hash.hex()})")

        last_block = self._channel_service.block_manager.get_blockchain().last_block
        if last_block is None:
            util.logger.debug("BlockChain has not been initialized yet.")
            return
        elif unconfirmed_block.header.height <= last_block.header.height:
            util.logger.debug("Ignore unconfirmed block because the block height is under last block height.")
            return
        elif self.__is_unconfirmed_block_by_complained_leader(unconfirmed_block):
            util.logger.debug("Ignore unconfirmed block because the block is made by complained leader.")
            return
        elif self._channel_service.state_machine.state not in ("Vote", "Watch", "LeaderComplain"):
            util.logger.debug(f"Can't add unconfirmed block in state({self._channel_service.state_machine.state}).")
            return

        self._channel_service.state_machine.vote(unconfirmed_block=unconfirmed_block)

    @message_queue_task
    async def announce_confirmed_block(self, serialized_block, commit_state="{}"):
        try:
            if self._channel_service.state_machine.state != "Watch":
                return
            blockchain = self._channel_service.block_manager.get_blockchain()
            json_block = json.loads(serialized_block)

            block_height = blockchain.block_versioner.get_height(json_block)
            block_version = blockchain.block_versioner.get_version(block_height)
            bs = BlockSerializer.new(block_version, blockchain.tx_versioner)

            confirmed_block = bs.deserialize(json_block)
            util.logger.spam(f"channel_inner_service:announce_confirmed_block\n "
                             f"hash({confirmed_block.header.hash.hex()}) "
                             f"block height({confirmed_block.header.height}), "
                             f"commit_state({commit_state})")

            header: blocks.v0_1a.BlockHeader = confirmed_block.header
            if not header.commit_state:
                bb = BlockBuilder.from_new(confirmed_block, blockchain.tx_versioner)
                confirmed_block = bb.build()  # to generate commit_state
                header = confirmed_block.header
            try:
                commit_state = ast.literal_eval(commit_state)
            except Exception as e:
                logging.warning(f"channel_inner_service:announce_confirmed_block FAIL get commit_state_dict, "
                                f"error by : {e}")

            if header.commit_state != commit_state:
                raise RuntimeError(f"Commit states does not match. "
                                   f"Generated {header.commit_state}, Received {commit_state}")

            if self._channel_service.block_manager.get_blockchain().block_height < confirmed_block.header.height:
                self._channel_service.block_manager.add_confirmed_block(confirmed_block)
            else:
                logging.debug(f"channel_inner_service:announce_confirmed_block "
                              f"already synced block height({confirmed_block.header.height})")
            response_code = message_code.Response.success
        except Exception as e:
            logging.error(f"announce confirmed block error : {e}")
            response_code = message_code.Response.fail
        return response_code

    @message_queue_task
    def block_sync(self, block_hash, block_height):
        blockchain = self._channel_service.block_manager.get_blockchain()

        response_message = None
        block: Block = None
        if block_hash != "":
            block = blockchain.find_block_by_hash(block_hash)
        elif block_height != -1:
            block = blockchain.find_block_by_height(block_height)
        else:
            response_message = message_code.Response.fail_not_enough_data

        if blockchain.last_unconfirmed_block is None:
            unconfirmed_block_height = -1
        else:
            unconfirmed_block_height = blockchain.last_unconfirmed_block.header.height

        if block is None:
            if response_message is None:
                response_message = message_code.Response.fail_wrong_block_hash
            return response_message, -1, blockchain.block_height, unconfirmed_block_height, None, None

        confirm_info = None
        if block.header.height <= blockchain.block_height:
            confirm_info = blockchain.find_confirm_info_by_hash(block.header.hash)

        return message_code.Response.success, block.header.height, blockchain.block_height, unconfirmed_block_height,\
            confirm_info, blockchain.block_dumps(block)

    @message_queue_task(type_=MessageQueueType.Worker)
    def add_audience(self, peer_target) -> None:
        peer = self._channel_service.peer_manager.get_peer_by_target(peer_target)
        if not peer:
            util.logger.debug(f"There is no peer peer_target({peer_target})")
        self._channel_service.broadcast_scheduler.schedule_job(BroadcastCommand.SUBSCRIBE, peer_target)

    @message_queue_task(type_=MessageQueueType.Worker)
    def remove_audience(self, peer_target) -> None:
        self._channel_service.broadcast_scheduler.schedule_job(BroadcastCommand.UNSUBSCRIBE, peer_target)

    @message_queue_task(type_=MessageQueueType.Worker)
    def announce_new_peer(self, peer_info_dumped, peer_target) -> None:
        try:
            peer_info = PeerInfo.load(peer_info_dumped)
        except Exception as e:
            traceback.print_exc()
            logging.error(f"Invalid peer info. peer_target={peer_target}, exception={e}")
            return

        logging.debug("Add New Peer: " + str(peer_info.peer_id))

        peer_manager = self._channel_service.peer_manager
        peer_manager.add_peer(peer_info)
        # broadcast the new peer to the others for adding an audience
        self._channel_service.broadcast_scheduler.schedule_job(BroadcastCommand.SUBSCRIBE, peer_target)

        logging.debug("Try save peer list...")
        # self._channel_service.save_peer_manager(peer_manager)
        self._channel_service.show_peers()

        if conf.CONSENSUS_ALGORITHM == conf.ConsensusAlgorithm.lft:
            quorum, complain_quorum = peer_manager.get_quorum()
            self._channel_service.consensus.set_quorum(quorum=quorum, complain_quorum=complain_quorum)

    @message_queue_task(type_=MessageQueueType.Worker)
    def delete_peer(self, peer_id, group_id) -> None:
        self._channel_service.peer_manager.remove_peer(peer_id, group_id)

    @message_queue_task(type_=MessageQueueType.Worker)
    def vote_unconfirmed_block(self, peer_id, group_id, block_hash: Hash32, vote_code) -> None:
        block_manager = self._channel_service.block_manager
        util.logger.spam(f"channel_inner_service:vote_unconfirmed_block "
                         f"({ChannelProperty().name}) block_hash({block_hash})")

        util.logger.debug("Peer vote to : " + block_hash.hex()[:8] + " " + str(vote_code) + f"from {peer_id[:8]}")

        block_manager.candidate_blocks.add_vote(
            block_hash,
            group_id,
            peer_id,
            (False, True)[vote_code == message_code.Response.success_validate_block]
        )

        if self._channel_service.state_machine.state == "BlockGenerate":
            if block_manager.consensus_algorithm:
                block_manager.consensus_algorithm.vote(
                    block_hash,
                    (False, True)[vote_code == message_code.Response.success_validate_block],
                    peer_id,
                    group_id)

    @message_queue_task(type_=MessageQueueType.Worker)
    async def complain_leader(self, complained_leader_id, new_leader_id, block_height, peer_id, group_id) -> None:
        block_manager = self._channel_service.block_manager
        util.logger.notice(f"channel_inner_service:complain_leader "
                           f"complain_leader_id({complained_leader_id}), "
                           f"new_leader_id({new_leader_id}), "
                           f"block_height({block_height})")

        block_manager.epoch.add_complain(
            complained_leader_id, new_leader_id, block_height, peer_id, group_id
        )

        next_new_leader = block_manager.epoch.complain_result()
        if next_new_leader:
            await self._channel_service.reset_leader(next_new_leader, complained=True)
            self._channel_service.reset_leader_complain_timer()

    @message_queue_task
    def get_invoke_result(self, tx_hash):
        try:
            invoke_result = self._channel_service.block_manager.get_invoke_result(tx_hash)
            invoke_result_str = json.dumps(invoke_result)
            response_code = message_code.Response.success
            logging.debug('invoke_result : ' + invoke_result_str)

            util.apm_event(ChannelProperty().peer_id, {
                'event_type': 'GetInvokeResult',
                'peer_id': ChannelProperty().peer_id,
                'peer_name': conf.PEER_NAME,
                'channel_name': ChannelProperty().name,
                'data': {'invoke_result': invoke_result, 'tx_hash': tx_hash}})

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
            util.apm_event(ChannelProperty().peer_id, {
                'event_type': 'Error',
                'peer_id': ChannelProperty().peer_id,
                'peer_name': conf.PEER_NAME,
                'channel_name': ChannelProperty().name,
                'data': {
                    'error_type': 'InvokeResultError',
                    'code': message_code.Response.fail,
                    'message': f"get invoke result error : {e}"}})
            return message_code.Response.fail, None

    @message_queue_task
    async def get_block_v2(self, block_height, block_hash, block_data_filter, tx_data_filter):
        # This is a temporary function for v2 support of exchanges.
        block, block_filter, block_hash, _, fail_response_code, tx_filter = \
            await self.__get_block(block_data_filter, block_hash, block_height, tx_data_filter)
        if fail_response_code:
            return fail_response_code, block_hash, json.dumps({}), ""

        tx_versioner = self._channel_service.block_manager.get_blockchain().tx_versioner
        bs = BlockSerializer.new(block.header.version, tx_versioner)
        block_data_dict = bs.serialize(block)

        if block.header.height == 0:
            return message_code.Response.success, block_hash, json.dumps(block_data_dict), []

        confirmed_tx_list = block_data_dict["confirmed_transaction_list"]
        confirmed_tx_list_without_fail = []

        tss = {
            "genesis": TransactionSerializer.new("genesis", tx_versioner),
            "0x2": TransactionSerializer.new("0x2", tx_versioner),
            "0x3": TransactionSerializer.new("0x3", tx_versioner)
        }

        for tx in confirmed_tx_list:
            version = tx_versioner.get_version(tx)
            tx_hash = tss[version].get_hash(tx)

            invoke_result = self._channel_service.block_manager.get_invoke_result(tx_hash)

            if 'failure' in invoke_result:
                continue

            if tx_versioner.get_version(tx) == "0x3":
                step_used, step_price = int(invoke_result["stepUsed"], 16), int(invoke_result["stepPrice"], 16)
                tx["fee"] = hex(step_used * step_price)

            confirmed_tx_list_without_fail.append(tx)

        # Replace the existing confirmed_tx_list with v2 ver.
        block_data_dict["confirmed_transaction_list"] = confirmed_tx_list_without_fail
        block_data_json = json.dumps(block_data_dict)

        if fail_response_code:
            return fail_response_code, block_hash, json.dumps({}), []

        return message_code.Response.success, block_hash, block_data_json, []

    @message_queue_task
    async def get_block(self, block_height, block_hash, block_data_filter, tx_data_filter):
        block, block_filter, block_hash, confirm_info, fail_response_code, tx_filter = \
            await self.__get_block(block_data_filter, block_hash, block_height, tx_data_filter)

        if fail_response_code:
            return fail_response_code, block_hash, b"", json.dumps({}), ""

        tx_versioner = self._channel_service.block_manager.get_blockchain().tx_versioner
        bs = BlockSerializer.new(block.header.version, tx_versioner)
        block_dict = bs.serialize(block)
        return message_code.Response.success, block_hash, confirm_info, json.dumps(block_dict), []

    async def __get_block(self, block_data_filter, block_hash, block_height, tx_data_filter):
        blockchain = self._channel_service.block_manager.get_blockchain()
        if block_hash == "" and block_height == -1:
            block_hash = blockchain.last_block.header.hash.hex()
        block_filter = re.sub(r'\s', '', block_data_filter).split(",")
        tx_filter = re.sub(r'\s', '', tx_data_filter).split(",")

        block = None
        confirm_info = b''
        fail_response_code = None
        if block_hash:
            block = blockchain.find_block_by_hash(block_hash)
            confirm_info = blockchain.find_confirm_info_by_hash(Hash32.fromhex(block_hash, True))
            if block is None:
                fail_response_code = message_code.Response.fail_wrong_block_hash
        elif block_height != -1:
            block = blockchain.find_block_by_height(block_height)
            confirm_info = blockchain.find_confirm_info_by_height(block_height)
            if block is None:
                fail_response_code = message_code.Response.fail_wrong_block_height
        else:
            fail_response_code = message_code.Response.fail_wrong_block_hash

        return block, block_filter, block_hash, bytes(confirm_info), fail_response_code, tx_filter

    @message_queue_task
    def get_precommit_block(self, last_block_height: int):
        block_manager = self._channel_service.block_manager
        precommit_block = block_manager.get_blockchain().get_precommit_block()

        if precommit_block is None:
            return message_code.Response.fail, "there is no precommit block.", b""
        if precommit_block.height != last_block_height + 1:
            return message_code.Response.fail, "need block height sync.", b""

        block_dumped = block_manager.get_blockchain().block_dumps(precommit_block)
        return message_code.Response.success, "success", block_dumped

    @message_queue_task
    def get_tx_by_address(self, address, index):
        block_manager = self._channel_service.block_manager
        tx_list, next_index = block_manager.get_blockchain().get_tx_list_by_address(address=address, index=index)

        return tx_list, next_index

    @message_queue_task
    def get_score_status(self):
        score_status = ""
        try:
            score_status_response = self._channel_service.score_stub.call(
                "Request",
                loopchain_pb2.Message(code=message_code.Request.status)
            )

            logging.debug("Get Score Status : " + str(score_status_response))

        except Exception as e:
            logging.debug("Score Service Already stop by other reason. %s", e)

        else:
            if score_status_response.code == message_code.Response.success:
                score_status = score_status_response.meta

        return score_status

    @message_queue_task
    async def get_tx_proof(self, tx_hash: str) -> Union[list, dict]:
        blockchain = self._channel_service.block_manager.get_blockchain()
        try:
            proof = blockchain.get_transaction_proof(Hash32.fromhex(tx_hash))
        except Exception as e:
            return make_error_response(JsonError.INVALID_PARAMS, str(e))

        try:
            return make_proof_serializable(proof)
        except Exception as e:
            return make_error_response(JsonError.INTERNAL_ERROR, str(e))

    @message_queue_task
    async def prove_tx(self, tx_hash: str, proof: list) -> Union[str, dict]:
        blockchain = self._channel_service.block_manager.get_blockchain()
        try:
            proof = make_proof_deserializable(proof)
        except Exception as e:
            return make_error_response(JsonError.INTERNAL_ERROR, str(e))

        try:
            return "0x1" if blockchain.prove_transaction(Hash32.fromhex(tx_hash), proof) else "0x0"
        except Exception as e:
            return make_error_response(JsonError.INVALID_PARAMS, str(e))

    @message_queue_task
    async def get_receipt_proof(self, tx_hash: str) -> Union[list, dict]:
        blockchain = self._channel_service.block_manager.get_blockchain()
        try:
            proof = blockchain.get_receipt_proof(Hash32.fromhex(tx_hash))
        except Exception as e:
            return make_error_response(JsonError.INVALID_PARAMS, str(e))

        try:
            return make_proof_serializable(proof)
        except Exception as e:
            return make_error_response(JsonError.INTERNAL_ERROR, str(e))

    @message_queue_task
    async def prove_receipt(self, tx_hash: str, proof: list) -> Union[str, dict]:
        blockchain = self._channel_service.block_manager.get_blockchain()
        try:
            proof = make_proof_deserializable(proof)
        except Exception as e:
            return make_error_response(JsonError.INTERNAL_ERROR, str(e))

        try:
            return "0x1" if blockchain.prove_receipt(Hash32.fromhex(tx_hash), proof) else "0x0"
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

    def __init__(self, amqp_target, route_key, username=None, password=None, **task_kwargs):
        super().__init__(amqp_target, route_key, username, password, **task_kwargs)
        self._task._citizen_condition_new_block = Condition(loop=self.loop)

    def _callback_connection_lost_callback(self, connection: RobustConnection):
        util.exit_and_msg("MQ Connection lost.")

    def notify_new_block(self):

        async def _notify():
            condition = self._task._citizen_condition_new_block
            async with condition:
                condition.notify_all()

        asyncio.run_coroutine_threadsafe(_notify(), self.loop)

    def init_sub_services(self):
        if self.loop != asyncio.get_event_loop():
            raise Exception("Must call this function in thread of self.loop")
        self._task.init_sub_service(self.loop)

    def cleanup(self):
        if self.loop != asyncio.get_event_loop():
            raise Exception("Must call this function in thread of self.loop")
        self._task.cleanup_sub_services()


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
