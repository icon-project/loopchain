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
"""stub wrapper for gRPC stub.
This object has own channel information and support re-generation of gRPC stub."""

import datetime
import logging
import time
import timeit

import grpc
from grpc._channel import _Rendezvous

import loopchain.utils as util
from loopchain import configure as conf
from loopchain.protos import loopchain_pb2, message_code


class StubManager:

    def __init__(self, target, stub_type, ssl_auth_type=conf.SSLAuthType.none):
        self.__target = target
        self.__stub_type = stub_type
        self.__ssl_auth_type = ssl_auth_type
        self.__stub = None
        self.__channel = None
        self.__stub_update_time = datetime.datetime.now()
        self.__last_succeed_time = time.monotonic()

        self.__make_stub(False)

    def __make_stub(self, is_stub_reuse=True):
        if util.datetime_diff_in_mins(self.__stub_update_time) >= conf.STUB_REUSE_TIMEOUT or \
                not is_stub_reuse or self.__stub is None:
            util.logger.spam(f"StubManager:__make_stub is_stub_reuse({is_stub_reuse}) self.__stub({self.__stub})")

            self.__stub, self.__channel = util.get_stub_to_server(
                self.__target, self.__stub_type, is_check_status=False, ssl_auth_type=self.__ssl_auth_type)
            self.__stub_update_time = datetime.datetime.now()
            if self.__stub:
                self.__update_last_succeed_time()
        else:
            pass

    @property
    def stub(self, is_stub_reuse=True):
        self.__make_stub(is_stub_reuse)

        return self.__stub

    @stub.setter
    def stub(self, value):
        self.__stub = value

    @property
    def target(self):
        return self.__target

    def elapsed_last_succeed_time(self):
        return time.monotonic() - self.__last_succeed_time

    def __update_last_succeed_time(self):
        self.__last_succeed_time = time.monotonic()

    def call(self, method_name, message, timeout=None, is_stub_reuse=True, is_raise=False):
        if timeout is None:
            timeout = conf.GRPC_TIMEOUT
        self.__make_stub(is_stub_reuse)

        try:
            stub_method = getattr(self.__stub, method_name)
            ret = stub_method(message, timeout)
            self.__update_last_succeed_time()
            return ret
        except Exception as e:
            logging.warning(f"gRPC call fail method_name({method_name}), message({message}): {e}")
            if is_raise:
                raise e

        return None

    @staticmethod
    def print_broadcast_fail(result: _Rendezvous):
        if result.code() != grpc.StatusCode.OK:
            logging.warning(f"call_async fail  : {result}\n"
                            f"cause by : {result.details()}")

    def call_async(self, method_name, message, call_back=None, timeout=None, is_stub_reuse=True) -> grpc.Future:
        if timeout is None:
            timeout = conf.GRPC_TIMEOUT
        if call_back is None:
            call_back = self.print_broadcast_fail
        self.__make_stub(is_stub_reuse)

        def done_callback(result: _Rendezvous):
            if result.code() == grpc.StatusCode.OK:
                self.__update_last_succeed_time()
            call_back(result)

        try:
            stub_method = getattr(self.__stub, method_name)
            feature_future = stub_method.future(message, timeout)
            feature_future.add_done_callback(done_callback)
            return feature_future
        except Exception as e:
            logging.warning(f"gRPC call_async fail method_name({method_name}), message({message}): {e}, "
                            f"target({self.__target})")

    def call_in_time(self, method_name, message, time_out_seconds=None, is_stub_reuse=True):
        """Try gRPC call. If it fails try again until time out (seconds)

        :param method_name:
        :param message:
        :param time_out_seconds:
        :param is_stub_reuse:
        :return:
        """
        if time_out_seconds is None:
            time_out_seconds = conf.CONNECTION_RETRY_TIMEOUT
        self.__make_stub(is_stub_reuse)

        stub_method = getattr(self.__stub, method_name)

        start_time = timeit.default_timer()
        duration = timeit.default_timer() - start_time

        while duration < time_out_seconds:
            try:
                return stub_method(message, conf.GRPC_TIMEOUT)
            except Exception as e:
                # logging.debug(f"retry request_server_in_time({method_name}): {e}")
                logging.debug("duration(" + str(duration)
                              + ") interval(" + str(conf.CONNECTION_RETRY_INTERVAL)
                              + ") timeout(" + str(time_out_seconds) + ")")

            # RETRY_INTERVAL 만큼 대기후 TIMEOUT 전이면 다시 시도
            time.sleep(conf.CONNECTION_RETRY_INTERVAL)
            self.__make_stub(False)
            duration = timeit.default_timer() - start_time

        return None

    def call_in_times(self, method_name, message,
                      retry_times=None,
                      is_stub_reuse=True,
                      timeout=conf.GRPC_TIMEOUT):
        """Try gRPC call. If it fails try again until "retry_times"

        :param method_name:
        :param message:
        :param retry_times:
        :param is_stub_reuse:
        :param timeout:
        :return:
        """
        retry_times = conf.BROADCAST_RETRY_TIMES if retry_times is None else retry_times

        self.__make_stub(is_stub_reuse)
        stub_method = getattr(self.__stub, method_name)

        while retry_times > 0:
            try:
                return stub_method(message, timeout)
            except Exception as e:
                logging.debug(f"retry request_server_in_times({method_name}): {e}")

            time.sleep(conf.CONNECTION_RETRY_INTERVAL)
            self.__make_stub(False)
            retry_times -= 1

        return None

    def check_status(self):
        try:
            self.__stub.Request(loopchain_pb2.Message(code=message_code.Request.status), conf.GRPC_TIMEOUT)
            return True
        except Exception as e:
            logging.warning(f"stub_manager:check_status is Fail reason({e})")
            return False

    @staticmethod
    def get_stub_manager_to_server(target, stub_class, time_out_seconds=None,
                                   is_allow_null_stub=False, ssl_auth_type=conf.SSLAuthType.none):
        """gRPC connection to server

        :return: stub manager to server
        """

        if time_out_seconds is None:
            time_out_seconds = conf.CONNECTION_RETRY_TIMEOUT
        stub_manager = StubManager(target, stub_class, ssl_auth_type)
        start_time = timeit.default_timer()
        duration = timeit.default_timer() - start_time

        while duration < time_out_seconds:
            try:
                logging.debug("(stub_manager) get stub to server target: " + str(target))
                stub_manager.stub.Request(loopchain_pb2.Message(
                    code=message_code.Request.status,
                    message="get_stub_manager_to_server"), conf.GRPC_TIMEOUT)
                return stub_manager
            except Exception as e:
                if is_allow_null_stub:
                    return stub_manager
                logging.warning("Connect to Server Error(get_stub_manager_to_server): " + str(e))
                logging.debug("duration(" + str(duration)
                              + ") interval(" + str(conf.CONNECTION_RETRY_INTERVAL)
                              + ") timeout(" + str(time_out_seconds) + ")")
                # RETRY_INTERVAL 만큼 대기후 TIMEOUT 전이면 다시 시도
                time.sleep(conf.CONNECTION_RETRY_INTERVAL)
                duration = timeit.default_timer() - start_time

        return None
