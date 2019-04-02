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
import queue
import threading
import signal
import abc
import time
import os
import multiprocessing as mp
from concurrent import futures
from enum import Enum
from functools import partial

import grpc
from grpc._channel import _Rendezvous

from loopchain import configure as conf, utils as util
from loopchain.baseservice import StubManager, ObjectManager, CommonThread, BroadcastCommand, \
    TimerService, Timer
from loopchain.baseservice.tx_item_helper import TxItem
from loopchain.protos import loopchain_pb2_grpc, loopchain_pb2
from loopchain.baseservice.module_process import ModuleProcess, ModuleProcessProperties


class PeerThreadStatus(Enum):
    normal = 0
    leader_complained = 1


class _Broadcaster:
    """broadcast class for each channel"""

    THREAD_INFO_KEY = "thread_info"
    THREAD_VARIABLE_STUB_TO_SELF_PEER = "stub_to_self_peer"
    THREAD_VARIABLE_PEER_STATUS = "peer_status"

    SELF_PEER_TARGET_KEY = "self_peer_target"
    LEADER_PEER_TARGET_KEY = "leader_peer_target"

    def __init__(self, channel: str, self_target: str=None):
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
            BroadcastCommand.BROADCAST: self.__handler_broadcast,
            BroadcastCommand.MAKE_SELF_PEER_CONNECTION: self.__handler_connect_to_self_peer,
        }

        self.__broadcast_with_self_target_methods = {
            "AddTx",
            "AddTxList",
            "BroadcastVote"
        }

        self.stored_tx = queue.Queue()

        self.__timer_service = TimerService()

    @property
    def is_running(self):
        return self.__timer_service.is_run()

    def start(self):
        self.__timer_service.start()

    def stop(self):
        if self.__timer_service.is_run():
            self.__timer_service.stop()
            self.__timer_service.wait()

    def handle_command(self, command, params):
        func = self.__handler_map[command]
        func(params)

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
                if stub_manager is None:
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
            stub_manager: StubManager = self.__audience[peer_target]
            if stub_manager is None:
                logging.debug(f"broadcast_thread:__call_async_to_target Failed to connect to ({peer_target}).")
                return
            call_back_partial = partial(self.__broadcast_retry_async,
                                        peer_target,
                                        method_name,
                                        method_param,
                                        retry_times,
                                        timeout,
                                        stub_manager.stub)
            stub_manager.call_async(method_name=method_name,
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
            try:
                stub_manager: StubManager = self.__audience[target]
                if stub_manager is None:
                    logging.debug(f"broadcast_thread:__broadcast_run_sync Failed to connect to ({target}).")
                    continue

                response = stub_manager.call_in_times(method_name=method_name,
                                                      message=method_param,
                                                      timeout=timeout,
                                                      retry_times=retry_times)
                if response is None:
                    logging.warning(f"broadcast_thread:__broadcast_run_sync fail ({method_name}) "
                                    f"target({target}) ")
            except KeyError as e:
                logging.debug(f"broadcast_thread:__broadcast_run_sync ({target}) not in audience. ({e})")

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
            if self.__self_target is not None and method_name not in self.__broadcast_with_self_target_methods:
                peer_targets.remove(self.__self_target)
            return peer_targets


class BroadcastScheduler(metaclass=abc.ABCMeta):
    def __init__(self):
        self.__schedule_listeners = dict()

    @abc.abstractmethod
    def start(self):
        raise NotImplementedError("start function is interface method")

    @abc.abstractmethod
    def stop(self):
        raise NotImplementedError("stop function is interface method")

    @abc.abstractmethod
    def wait(self):
        raise NotImplementedError("stop function is interface method")

    @abc.abstractmethod
    def _put_command(self, command, params, block=False, block_timeout=None):
        raise NotImplementedError("_put_command function is interface method")

    def add_schedule_listener(self, callback, commands: tuple):
        if not commands:
            raise ValueError("commands parameter is required")

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

    def schedule_job(self, command, params, block=False, block_timeout=None):
        self._put_command(command, params, block=block, block_timeout=block_timeout)
        self.__perform_schedule_listener(command, params)

    def schedule_broadcast(self, method_name, method_param, *, retry_times=None, timeout=None):
        kwargs = {}
        if retry_times is not None:
            kwargs['retry_times'] = retry_times
        if timeout is not None:
            kwargs['timeout'] = timeout
        self.schedule_job(BroadcastCommand.BROADCAST, (method_name, method_param, kwargs))


class _BroadcastThread(CommonThread):
    def __init__(self, channel: str, self_target: str=None):
        self.broadcast_queue = queue.PriorityQueue()
        self.__broadcast_pool = futures.ThreadPoolExecutor(conf.MAX_BROADCAST_WORKERS, "BroadcastThread")
        self.__broadcaster = _Broadcaster(channel, self_target)

    def stop(self):
        super().stop()
        self.broadcast_queue.put((None, None, None, None))
        self.__broadcast_pool.shutdown(False)

    def run(self, event: threading.Event):
        event.set()
        self.__broadcaster.start()

        def _callback(curr_future: futures.Future, executor_future: futures.Future):
            if executor_future.exception():
                curr_future.set_exception(executor_future.exception())
                logging.error(executor_future.exception())
            else:
                curr_future.set_result(executor_future.result())

        while self.is_run():
            priority, command, params, future = self.broadcast_queue.get()
            if command is None:
                break

            return_future = self.__broadcast_pool.submit(self.__broadcaster.handle_command, command, params)
            if future is not None:
                return_future.add_done_callback(partial(_callback, future))


class _BroadcastSchedulerThread(BroadcastScheduler):
    def __init__(self, channel: str, self_target: str=None):
        super().__init__()

        self.__broadcast_thread = _BroadcastThread(channel, self_target=self_target)

    def start(self):
        self.__broadcast_thread.start()

    def stop(self):
        self.__broadcast_thread.stop()

    def wait(self):
        self.__broadcast_thread.wait()

    def _put_command(self, command, params, block=False, block_timeout=None):
        if command == BroadcastCommand.CREATE_TX:
            priority = (10, time.time())
        elif isinstance(params, tuple) and params[0] == "AddTx":
            priority = (10, time.time())
        else:
            priority = (0, time.time())

        future = futures.Future() if block else None
        self.__broadcast_thread.broadcast_queue.put((priority, command, params, future))
        if future is not None:
            future.result(block_timeout)


class _BroadcastSchedulerMp(BroadcastScheduler):
    def __init__(self, channel: str, self_target: str=None):
        super().__init__()

        self.__channel = channel
        self.__self_target = self_target

        self.__process = ModuleProcess()

        self.__broadcast_queue = self.__process.Queue()
        self.__broadcast_queue.cancel_join_thread()

    @staticmethod
    def _main(broadcast_queue: mp.Queue, channel: str, self_target: str, properties: ModuleProcessProperties=None):
        if properties is not None:
            ModuleProcess.load_properties(properties, f"{channel}_broadcast")

        logging.info(f"BroadcastScheduler process({channel}) start")

        broadcast_queue.cancel_join_thread()

        broadcaster = _Broadcaster(channel, self_target)
        broadcaster.start()

        original_sigterm_handler = signal.getsignal(signal.SIGTERM)
        original_sigint_handler = signal.getsignal(signal.SIGINT)

        def _signal_handler(signal_num, frame):
            signal.signal(signal.SIGTERM, original_sigterm_handler)
            signal.signal(signal.SIGINT, original_sigint_handler)
            logging.error(f"BroadcastScheduler process({channel}) has been received signal({signal_num})")
            broadcast_queue.put((None, None))
            broadcaster.stop()

        signal.signal(signal.SIGTERM, _signal_handler)
        signal.signal(signal.SIGINT, _signal_handler)

        while True:
            command, params = broadcast_queue.get()
            if not broadcaster.is_running or command is None:
                break
            broadcaster.handle_command(command, params)

        while not broadcast_queue.empty():
            broadcast_queue.get()

        logging.info(f"BroadcastScheduler process({channel}) end")

    def start(self):
        def crash_callback_in_join_thread(process: ModuleProcess):
            os.kill(os.getpid(), signal.SIGTERM)

        args = (self.__broadcast_queue, self.__channel, self.__self_target)
        self.__process.start(target=_BroadcastSchedulerMp._main,
                             args=args,
                             crash_callback_in_join_thread=crash_callback_in_join_thread)

    def stop(self):
        logging.info(f"Terminate BroadcastScheduler process({self})")
        self.__process.terminate()

    def wait(self):
        self.__process.join()

    def _put_command(self, command, params, block=False, block_timeout=None):
        self.__broadcast_queue.put((command, params))


class BroadcastSchedulerFactory:
    @staticmethod
    def new(channel: str, self_target: str=None, is_multiprocessing: bool=None) -> BroadcastScheduler:
        if is_multiprocessing is None:
            is_multiprocessing = conf.IS_BROADCAST_MULTIPROCESSING

        if is_multiprocessing:
            return _BroadcastSchedulerMp(channel, self_target=self_target)
        else:
            return _BroadcastSchedulerThread(channel, self_target=self_target)
