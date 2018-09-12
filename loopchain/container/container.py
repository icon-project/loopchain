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
"""A module for containers on the loopchain """

import logging
import multiprocessing
import setproctitle
from concurrent import futures
from enum import Enum

import grpc

import loopchain.utils as util
from loopchain import configure as conf
from loopchain.baseservice import CommonProcess, MonitorAdapter, ObjectManager, Monitor, CommonSubprocess
from loopchain.protos import loopchain_pb2, loopchain_pb2_grpc, message_code
from loopchain.tools.grpc_helper import GRPCHelper
from loopchain.utils import command_arguments


class ServerType(Enum):
    REST_RS = 1
    REST_PEER = 2
    GRPC = 3


class Container(CommonProcess, MonitorAdapter):

    def __init__(self,
                 port,
                 server_type=ServerType.GRPC,
                 peer_ip=None,
                 process_name="",
                 channel="",
                 start_param_set=None):

        CommonProcess.__init__(self)
        if server_type == ServerType.GRPC:
            # monitoring gRPC Container
            MonitorAdapter.__init__(self, channel=channel, process_name=f"{process_name}")
        self._port = port
        self._type = server_type
        self._peer_ip = peer_ip
        self._process_name = process_name
        self._channel = channel
        self._start_param_set = start_param_set
        self._service_stub = None

    def is_alive(self):
        try:
            # util.logger.spam(f"{self._process_name} is_alive")
            response = self._service_stub.call(
                "Request",
                loopchain_pb2.Message(code=message_code.Request.is_alive))
            return True if response is not None else False
        except Exception as e:
            if self._service_stub is None:
                util.logger.spam(f"container:is_alive service_stub set now! ignore this exception({e})")
                peer_service = ObjectManager().peer_service
                if peer_service is not None:
                    self._service_stub = peer_service.channel_manager.get_score_container_stub(self._channel)
                return True
            logging.warning(f"container:is_alive has exception({e})")
            return False

    def re_start(self):
        Monitor().stop_wait_monitoring()
        ObjectManager().peer_service.channel_manager.stop_score_containers()
        ObjectManager().peer_service.service_stop()
        util.exit_and_msg(f"Score Container({self._channel}) Down!")

    def run(self, conn, event: multiprocessing.Event):
        logging.debug("Container run...")

        if self._type == ServerType.GRPC:
            logging.info(f'Container run grpc port {self._port}')

            setproctitle.setproctitle(f"{setproctitle.getproctitle()} {self._process_name}")

            server = grpc.server(futures.ThreadPoolExecutor(conf.MAX_WORKERS, "ContainerThread"))
            loopchain_pb2_grpc.add_ContainerServicer_to_server(self, server)
            GRPCHelper().add_server_port(server, '[::]:' + str(self._port), conf.SSLAuthType.none)

            logging.info(f'Container run complete grpc port {self._port}')
        elif self._type == ServerType.REST_PEER:
            args = ['python3', '-m', 'loopchain', 'rest', '-p', str(self._port)]
            args += command_arguments.get_raw_commands_by_filter(
                command_arguments.Type.AMQPTarget,
                command_arguments.Type.AMQPKey,
                command_arguments.Type.Develop,
                command_arguments.Type.ConfigurationFilePath
            )
            server = CommonSubprocess(args)
            api_port = self._port + conf.PORT_DIFF_REST_SERVICE_CONTAINER
            server.set_proctitle(f"{setproctitle.getproctitle()} RestServer api_port({api_port})")
        else:
            args = ['python3', '-m', 'loopchain', 'rest-rs', '-p', str(self._port)]
            args += command_arguments.get_raw_commands_by_filter(
                command_arguments.Type.Develop,
                command_arguments.Type.ConfigurationFilePath
            )

            api_port = self._port + conf.PORT_DIFF_REST_SERVICE_CONTAINER
            server = CommonSubprocess(args)
            server.set_proctitle(f"{setproctitle.getproctitle()} RestServerRS api_port({api_port})")

        logging.info(f'Container run complete port {self._port}')

        # complete init
        event.set()

        if self._type == ServerType.GRPC:
            self._append_monitor()

        command = None
        while command != "quit":
            try:
                command, param = conn.recv()  # Queue 에 내용이 들어올 때까지 여기서 대기 된다. 따라서 Sleep 이 필요 없다.
                logging.debug("Container got: " + str(param))
            except Exception as e:
                logging.warning("Container conn.recv() error: " + str(e))
            except KeyboardInterrupt:
                pass

        if self._type == ServerType.GRPC:
            server.stop(0)
        else:
            server.stop()

        logging.info("Server Container Ended.")
