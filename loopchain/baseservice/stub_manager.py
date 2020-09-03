"""stub wrapper for gRPC stub.
This object has own channel information and support re-generation of gRPC stub."""
import datetime
import logging
import time

import grpc
from grpc._channel import _Rendezvous

import loopchain.utils as util
from loopchain import configure as conf


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
                self.__target, self.__stub_type, ssl_auth_type=self.__ssl_auth_type)
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
