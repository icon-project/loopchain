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
"""Class for managing Peer and Radio station """

import logging
import threading
import time
from concurrent import futures

import grpc

import loopchain.utils as util
from loopchain import configure as conf
from loopchain.baseservice import CommonThread, ObjectManager
from loopchain.tools.grpc_helper import GRPCHelper


# Changing the import location will cause a pickle error.


class CommonService(CommonThread):
    """Manage common part of 'Peer' and 'Radio station' especially broadcast service"""

    def __init__(self, gRPC_module, inner_service_port=None):
        super().__init__()
        self.__peer_id = None if ObjectManager().peer_service is None else ObjectManager().peer_service.peer_id

        # for peer_service, it refers to peer_inner_service / for rs_service, it refers to rs_admin_service
        self.inner_server = grpc.server(futures.ThreadPoolExecutor(conf.MAX_WORKERS, "CommonInnerThread"))
        self.outer_server = grpc.server(futures.ThreadPoolExecutor(conf.MAX_WORKERS, "CommonOuterThread"))

        # members for private, It helps simplicity of code intelligence
        self.__gRPC_module = gRPC_module
        self.__port = 0
        self.__inner_service_port = inner_service_port
        self.__peer_target = None
        if inner_service_port is not None:  # It means this is Peer's CommonService not RS.
            peer_port = inner_service_port - conf.PORT_DIFF_INNER_SERVICE
            self.__peer_target = util.get_private_ip() + ":" + str(peer_port)
        self.__group_id = ""

    def start(self, port, peer_id="", group_id=""):
        self.__port = port
        if self.__inner_service_port is None:
            self.__inner_service_port = int(port) + conf.PORT_DIFF_INNER_SERVICE
        self.__peer_id = peer_id
        self.__group_id = group_id
        CommonThread.start(self)

    def run(self, event: threading.Event):
        target_host = '[::]:' + str(self.__port)
        GRPCHelper().add_server_port(self.outer_server, target_host)

        target_host = conf.INNER_SERVER_BIND_IP + ':' + str(self.__inner_service_port)
        GRPCHelper().add_server_port(self.inner_server, target_host, conf.SSLAuthType.none)

        # Block Generator 에 subscribe 하게 되면 Block Generator 는 peer 에 channel 생성을 요청한다.
        # 따라서 peer 의 gRPC 서버가 완전히 시작된 후 Block Generator 로 subscribe 요청을 하여야 한다.

        event.set()

        try:
            logging.info(f'CommonService is running')
            while self.is_run():
                time.sleep(conf.SLEEP_SECONDS_IN_SERVICE_NONE)
        except KeyboardInterrupt:
            logging.info("Server Stop by KeyboardInterrupt")
        finally:
            if self.__inner_service_port is not None:
                self.inner_server.stop(0)
            self.outer_server.stop(0)

        logging.info("Server thread Ended.")
