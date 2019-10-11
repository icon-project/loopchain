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
"""REST Service for Peer"""

import logging
import multiprocessing

import setproctitle

from loopchain import utils as util
from loopchain.baseservice import CommonProcess, CommonSubprocess
from loopchain.utils import command_arguments
from loopchain import configure as conf


class RestService(CommonProcess):
    def __init__(self, port, peer_ip=None):
        super().__init__()
        self._port = port
        self._peer_ip = peer_ip or util.get_private_ip()
        self.start()

    def run(self, conn, event: multiprocessing.Event):
        logging.debug("RestService run...")

        args = ['python3', '-m', 'loopchain', 'rest', '-p', str(self._port)]
        args += command_arguments.get_raw_commands_by_filter(
            command_arguments.Type.AMQPKey,
            command_arguments.Type.MainNet,
            command_arguments.Type.TestNet,
            command_arguments.Type.RadioStationTarget
        )
        server = CommonSubprocess(args)
        api_port = self._port + conf.PORT_DIFF_REST_SERVICE_CONTAINER
        server.set_proctitle(f"{setproctitle.getproctitle()} RestServer api_port({api_port})")
        logging.info(f'RestService run complete port {self._port}')

        # complete init
        event.set()

        command = None
        while command != "quit":
            try:
                command, param = conn.recv()
                logging.debug(f"RestService got: {param}")
            except Exception as e:
                logging.warning(f"RestService conn.recv() error: {e}")
            except KeyboardInterrupt:
                pass

        server.stop()
        logging.info("RestService Ended.")
