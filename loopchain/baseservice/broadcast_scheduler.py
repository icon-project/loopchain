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
"""gRPC broadcast thread"""

import logging
import pickle
import queue
import threading
import time
from concurrent import futures
from enum import Enum
from functools import partial

import grpc
from grpc._channel import _Rendezvous

from loopchain import configure as conf, utils as util
from loopchain.baseservice import StubManager, PeerManager, ObjectManager, CommonThread, BroadcastCommand, \
    TimerService, Timer
from loopchain.baseservice.tx_item_helper import *
from loopchain.protos import loopchain_pb2_grpc


class PeerThreadStatus(Enum):
    normal = 0
    leader_complained = 1


class BroadcastScheduler(CommonThread):
    """broadcast class for each channel"""

    THREAD_INFO_KEY = "thread_info"
    THREAD_VARIABLE_STUB_TO_SELF_PEER = "stub_to_self_peer"
    THREAD_VARIABLE_PEER_STATUS = "peer_status"

    SELF_PEER_TARGET_KEY = "self_peer_target"
    LEADER_PEER_TARGET_KEY = "leader_peer_target"

    def __init__(self, channel="", self_target=""):
        super().__init__()

        self.__channel = channel
        self.__self_target = self_target

        self.__audience = {}  # self.__audience[peer_target] = stub_manager
        self.__thread_variables = dict()
        self.__thread_variables[self.THREAD_VARIABLE_PEER_STATUS] = PeerThreadStatus.normal

        if conf.IS_BROADCAST_ASYNC:
            self.__broadcast_run = self.__broadcast_run_async
        else:
            self.__broadcast_run = self.__broadcast_run_sync

        self.__handler_map = {
            BroadcastCommand.CREATE_TX: self.__handler_create_tx,
            BroadcastCommand.CONNECT_TO_LEADER: self.__handler_connect_to_leader,
            BroadcastCommand.SUBSCRIBE: self.__handler_subscribe,
            BroadcastCommand.UNSUBSCRIBE: self.__handler_unsubscribe,
            BroadcastCommand.UPDATE_AUDIENCE: self.__handler_update_audience,
            BroadcastCommand.BROADCAST: self.__handler_broadcast,
            BroadcastCommand.MAKE_SELF_PEER_CONNECTION: self.__handler_connect_to_self_peer,
        }

        self.__broadcast_with_self_target_methods = {
            "AddTx",
            "AddTxList",
            "BroadcastVote"
        }

        self.stored_tx = queue.Queue()

        self.__broadcast_pool = futures.ThreadPoolExecutor(conf.MAX_BROADCAST_WORKERS, "BroadcastThread")
        self.__broadcast_queue = queue.PriorityQueue()

        self.__timer_service = TimerService()

        self.__schedule_listeners = dict()

    def stop(self):
        super().stop()
        self.__broadcast_queue.put((None, None, None, None))
        self.__broadcast_pool.shutdown(False)
        if self.__timer_service.is_run():
            self.__timer_service.stop()
            self.__timer_service.wait()

    def run(self, event: threading.Event):
        event.set()
        self.__timer_service.start()

        def _callback(curr_future: futures.Future, executor_future: futures.Future):
            if executor_future.exception():
                curr_future.set_exception(executor_future.exception())
                logging.error(executor_future.exception())
            else:
                curr_future.set_result(executor_future.result())

        while self.is_run():
            priority, command, params, future = self.__broadcast_queue.get()
            if command is None:
                break

            func = self.__handler_map[command]
            return_future = self.__broadcast_pool.submit(func, params)
            return_future.add_done_callback(partial(_callback, future))

    def add_schedule_listener(self, callback, commands=None):
        if commands is None:
            commands = self.__handler_map.keys()
        for cmd in commands:
            callbacks = self.__schedule_listeners.get(cmd)
            if callbacks is None:
                callbacks = []
                self.__schedule_listeners[cmd] = callbacks
            elif callback in callbacks:
                raise ValueError("callback is already in callbacks")
            callbacks.append(callback)

    def remove_schedule_listener(self, callback):
        removed = False
        for cmd in list(self.__schedule_listeners):
            callbacks = self.__schedule_listeners[cmd]
            try:
                callbacks.remove(callback)
                removed = True
                if len(callbacks):
                    del self.__schedule_listeners[cmd]
            except ValueError:
                pass
        if not removed:
            raise ValueError("callback is not in overserver callbacks")

    def __perform_schedule_listener(self, command, params):
        callbacks = self.__schedule_listeners.get(command)
        if callbacks:
            for cb in callbacks:
                cb(command, params)

    def schedule_job(self, command, params):
        if command == BroadcastCommand.CREATE_TX:
            priority = (10, time.time())
        elif isinstance(params, tuple) and params[0] == "AddTx":
            priority = (10, time.time())
        else:
            priority = (0, time.time())

        future = futures.Future()
        self.__broadcast_queue.put((priority, command, params, future))
        util.logger.spam(f"broadcast_scheduler:schedule_job qsize({self.__broadcast_queue.qsize()})")
        self.__perform_schedule_listener(command, params)
        return future

    def schedule_broadcast(self, method_name, method_param, *, retry_times=None, timeout=None):
        """등록된 모든 Peer 의 동일한 gRPC method 를 같은 파라미터로 호출한다.
        """
        # logging.warning("broadcast in process ==========================")
        # logging.debug("pickle method_param: " + str(pickle.dumps(method_param)))

        kwargs = {}
        if retry_times is not None:
            kwargs['retry_times'] = retry_times

        if timeout is not None:
            kwargs['timeout'] = timeout

        self.schedule_job(BroadcastCommand.BROADCAST, (method_name, method_param, kwargs))

    def __keep_grpc_connection(self, result, timeout, stub_manager: StubManager):
        return isinstance(result, _Rendezvous) \
               and result.code() in (grpc.StatusCode.DEADLINE_EXCEEDED, grpc.StatusCode.UNAVAILABLE) \
               and stub_manager.elapsed_last_succeed_time() < timeout

    def __broadcast_retry_async(self, peer_target, method_name, method_param, retry_times, timeout, stub, result):
        if isinstance(result, _Rendezvous) and result.code() == grpc.StatusCode.OK:
            return
        if isinstance(result, futures.Future) and not result.exception():
            return

        logging.debug(f"try retry to : peer_target({peer_target})\n")
        if retry_times > 0:
            try:
                stub_manager: StubManager = self.__audience[peer_target]
                if not stub_manager:
                    logging.warning(f"broadcast_thread:__broadcast_retry_async Failed to connect to ({peer_target}).")
                    return
                retry_times -= 1
                is_stub_reuse = stub_manager.stub != stub or self.__keep_grpc_connection(result, timeout, stub_manager)
                self.__call_async_to_target(peer_target, method_name, method_param, is_stub_reuse, retry_times, timeout)
            except KeyError as e:
                logging.debug(f"broadcast_thread:__broadcast_retry_async ({peer_target}) not in audience. ({e})")
        else:
            if isinstance(result, _Rendezvous):
                exception = result.details()
            elif isinstance(result, futures.Future):
                exception = result.exception()

            logging.warning(f"__broadcast_run_async fail({result})\n"
                            f"cause by: {exception}\n"
                            f"peer_target({peer_target})\n"
                            f"method_name({method_name})\n"
                            f"retry_remains({retry_times})\n"
                            f"timeout({timeout})")

    def __call_async_to_target(self, peer_target, method_name, method_param, is_stub_reuse, retry_times, timeout):
        try:
            stub_item: StubManager = self.__audience[peer_target]
            if not stub_item:
                logging.debug(f"broadcast_thread:__call_async_to_target Failed to connect to ({peer_target}).")
                return
            call_back_partial = partial(self.__broadcast_retry_async,
                                        peer_target,
                                        method_name,
                                        method_param,
                                        retry_times,
                                        timeout,
                                        stub_item.stub)
            stub_item.call_async(method_name=method_name,
                                 message=method_param,
                                 is_stub_reuse=is_stub_reuse,
                                 call_back=call_back_partial,
                                 timeout=timeout)
        except KeyError as e:
            logging.debug(f"broadcast_thread:__call_async_to_target ({peer_target}) not in audience. ({e})")

    def __broadcast_run_async(self, method_name, method_param, retry_times=None, timeout=None):
        """call gRPC interface of audience

        :param method_name: gRPC interface
        :param method_param: gRPC message
        """

        if timeout is None:
            timeout = conf.GRPC_TIMEOUT_BROADCAST_RETRY

        retry_times = conf.BROADCAST_RETRY_TIMES if retry_times is None else retry_times
        # logging.debug(f"broadcast({method_name}) async... ({len(self.__audience)})")

        for target in self.__get_broadcast_targets(method_name):
            # util.logger.debug(f"method_name({method_name}), peer_target({target})")
            self.__call_async_to_target(target, method_name, method_param, True, retry_times, timeout)

    def __broadcast_run_sync(self, method_name, method_param, retry_times=None, timeout=None):
        """call gRPC interface of audience

        :param method_name: gRPC interface
        :param method_param: gRPC message
        """
        # logging.debug(f"broadcast({method_name}) sync... ({len(self.__audience)})")

        if timeout is None:
            timeout = conf.GRPC_TIMEOUT_BROADCAST_RETRY

        retry_times = conf.BROADCAST_RETRY_TIMES if retry_times is None else retry_times

        for target in self.__get_broadcast_targets(method_name):
            if target in self.__audience.keys():
                stub_item = self.__audience[target]

            response = stub_item.call_in_times(
                method_name=method_name,
                message=method_param,
                timeout=timeout,
                retry_times=retry_times)

            if response is None:
                logging.warning(f"broadcast_thread:__broadcast_run_sync fail ({method_name}) "
                                f"target({target}) ")

    def __handler_subscribe(self, audience_target):
        logging.debug("BroadcastThread received subscribe command peer_target: " + str(audience_target))
        if audience_target not in self.__audience:
            stub_manager = StubManager.get_stub_manager_to_server(
                audience_target, loopchain_pb2_grpc.PeerServiceStub,
                time_out_seconds=conf.CONNECTION_RETRY_TIMEOUT_WHEN_INITIAL,
                is_allow_null_stub=True,
                ssl_auth_type=conf.GRPC_SSL_TYPE
            )
            self.__audience[audience_target] = stub_manager

    def __handler_unsubscribe(self, audience_target):
        # logging.debug(f"BroadcastThread received unsubscribe command peer_target({unsubscribe_peer_target})")
        try:
            del self.__audience[audience_target]
        except KeyError:
            logging.warning(f"Already deleted peer: {audience_target}")

    def __handler_update_audience(self, audience_param):
        util.logger.spam(f"broadcast_thread:__handler_update_audience audience_param({audience_param})")
        peer_manager = PeerManager(self.__channel)
        peer_list_data = pickle.loads(audience_param)
        peer_manager.load(peer_list_data, False)

        for peer_id in list(peer_manager.peer_list[conf.ALL_GROUP_ID]):
            peer_each = peer_manager.peer_list[conf.ALL_GROUP_ID][peer_id]
            if peer_each.target != self.__self_target:
                logging.warning(f"broadcast thread peer_targets({peer_each.target})")
                self.__handler_subscribe(peer_each.target)

    def __handler_broadcast(self, broadcast_param):
        # logging.debug("BroadcastThread received broadcast command")
        broadcast_method_name = broadcast_param[0]
        broadcast_method_param = broadcast_param[1]
        broadcast_method_kwparam = broadcast_param[2]
        # logging.debug("BroadcastThread method name: " + broadcast_method_name)
        # logging.debug("BroadcastThread method param: " + str(broadcast_method_param))
        self.__broadcast_run(broadcast_method_name, broadcast_method_param, **broadcast_method_kwparam)

    def __make_tx_list_message(self):
        tx_list = []
        tx_list_size = 0
        tx_list_count = 0
        remains = False
        while not self.stored_tx.empty():
            stored_tx_item = self.stored_tx.get()
            tx_list_size += len(stored_tx_item)
            tx_list_count += 1
            if tx_list_size >= conf.MAX_TX_SIZE_IN_BLOCK or tx_list_count >= conf.MAX_TX_COUNT_IN_ADDTX_LIST:
                self.stored_tx.put(stored_tx_item)
                remains = True
                break
            tx_list.append(stored_tx_item.get_tx_message())
        message = loopchain_pb2.TxSendList(
            channel=self.__channel,
            tx_list=tx_list
        )

        return remains, message

    def __send_tx_by_timer(self, **kwargs):
        # util.logger.spam(f"broadcast_scheduler:__send_tx_by_timer")
        if self.__thread_variables[self.THREAD_VARIABLE_PEER_STATUS] == PeerThreadStatus.leader_complained:
            logging.warning("Leader is complained your tx just stored in queue by temporally: "
                            + str(self.stored_tx.qsize()))
        else:
            # Send single tx for test
            # stored_tx_item = self.stored_tx.get()
            # self.__broadcast_run("AddTx", stored_tx_item.get_tx_message())

            # Send multiple tx
            remains, message = self.__make_tx_list_message()
            self.__broadcast_run("AddTxList", message)
            ObjectManager().channel_service.start_leader_complain_timer()
            if remains:
                self.__send_tx_in_timer()

    def __send_tx_in_timer(self, tx_item=None):
        # util.logger.spam(f"broadcast_scheduler:__send_tx_in_timer")
        duration = 0
        if tx_item:
            self.stored_tx.put(tx_item)
            duration = conf.SEND_TX_LIST_DURATION

        if TimerService.TIMER_KEY_ADD_TX not in self.__timer_service.timer_list:
            self.__timer_service.add_timer(
                TimerService.TIMER_KEY_ADD_TX,
                Timer(
                    target=TimerService.TIMER_KEY_ADD_TX,
                    duration=duration,
                    callback=self.__send_tx_by_timer,
                    callback_kwargs={}
                )
            )
        else:
            pass

    def __handler_create_tx(self, create_tx_param):
        # logging.debug(f"Broadcast create_tx....")
        try:
            tx_item = TxItem.create_tx_item(create_tx_param, self.__channel)
        except Exception as e:
            logging.warning(f"tx in channel({self.__channel})")
            logging.warning(f"__handler_create_tx: meta({create_tx_param})")
            logging.warning(f"tx dumps fail ({e})")
            return

        self.__send_tx_in_timer(tx_item)

    def __handler_connect_to_leader(self, connect_to_leader_param):
        # logging.debug("(tx thread) try... connect to leader: " + str(connect_to_leader_param))
        self.__thread_variables[self.LEADER_PEER_TARGET_KEY] = connect_to_leader_param

        # stub_to_self_peer = __thread_variables[self.THREAD_VARIABLE_STUB_TO_SELF_PEER]

        self.__thread_variables[self.THREAD_VARIABLE_PEER_STATUS] = PeerThreadStatus.normal

    def __handler_connect_to_self_peer(self, connect_param):
        # 자신을 생성한 부모 Peer 에 접속하기 위한 stub 을 만든다.
        # pipe 를 통한 return 은 pipe send 와 쌍이 맞지 않은 경우 오류를 발생시킬 수 있다.
        # 안전한 연결을 위하여 부모 프로세스와도 gRPC stub 을 이용하여 통신한다.
        logging.debug("try connect to self peer: " + str(connect_param))

        stub_to_self_peer = StubManager.get_stub_manager_to_server(
            connect_param, loopchain_pb2_grpc.InnerServiceStub,
            time_out_seconds=conf.CONNECTION_RETRY_TIMEOUT_WHEN_INITIAL,
            is_allow_null_stub=True,
            ssl_auth_type=conf.SSLAuthType.none
        )
        self.__thread_variables[self.SELF_PEER_TARGET_KEY] = connect_param
        self.__thread_variables[self.THREAD_VARIABLE_STUB_TO_SELF_PEER] = stub_to_self_peer

    def __get_broadcast_targets(self, method_name):

        peer_targets = list(self.__audience)
        if ObjectManager().rs_service:
            return peer_targets
        else:
            if method_name not in self.__broadcast_with_self_target_methods:
                peer_targets.remove(self.__self_target)
            return peer_targets
