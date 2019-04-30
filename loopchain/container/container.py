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
from enum import Enum

from loopchain import configure as conf
from loopchain.baseservice import CommonProcess, CommonSubprocess
from loopchain.utils import command_arguments


class ServerType(Enum):
    REST_RS = 1
    REST_PEER = 2


class Container(CommonProcess):

    def __init__(self,
                 port,
                 server_type=None,
                 peer_ip=None,
                 process_name="",
                 channel="",
                 start_param_set=None):

        CommonProcess.__init__(self)
        self._port = port
        self._type = server_type
        self._peer_ip = peer_ip
        self._process_name = process_name
        self._channel = channel
        self._start_param_set = start_param_set
        self._service_stub = None

    def run(self, conn, event: multiprocessing.Event):
        logging.debug("Container run...")

        if self._type == ServerType.REST_PEER:
            args = ['python3', '-m', 'loopchain', 'rest', '-p', str(self._port)]
            args += command_arguments.get_raw_commands_by_filter(
                command_arguments.Type.AMQPTarget,
                command_arguments.Type.AMQPKey,
                command_arguments.Type.Develop,
                command_arguments.Type.ConfigurationFilePath,
                command_arguments.Type.RadioStationTarget
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

        command = None
        while command != "quit":
            try:
                command, param = conn.recv()  # Queue 에 내용이 들어올 때까지 여기서 대기 된다. 따라서 Sleep 이 필요 없다.
                logging.debug("Container got: " + str(param))
            except Exception as e:
                logging.warning("Container conn.recv() error: " + str(e))
            except KeyboardInterrupt:
                pass

        server.stop()
        logging.info("Server Container Ended.")
