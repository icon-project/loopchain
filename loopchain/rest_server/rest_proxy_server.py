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
"""A module for server of Rest Proxy"""

import logging
import subprocess
import threading

from loopchain import configure as conf
from loopchain import utils as util
from loopchain.baseservice import CommonThread
from loopchain.utils import command_arguments


class RestProxyServer(CommonThread):
    """The purpose of this class is to avoid that RestProxyServer becomes defunct process"""

    def __init__(self, peer_port):
        super().__init__()

        self.__peer_port = peer_port
        self.__rest_proxy_port = peer_port + conf.PORT_DIFF_REST_SERVICE_CONTAINER

        self.__subprocess: subprocess.Popen = None

        self.start()

    def stop(self):
        self.__subprocess.terminate()
        super().stop()

    def run(self, event: threading.Event):
        # rest_proxy_port will be calculated in 'rest_proxy.py' again.
        # The reason passing peer_port to 'rest_proxy.py' is that rest_proxy should know which port it has to connect.
        args = ['python3', './rest_proxy.py', '-p', str(self.__peer_port)]
        args += command_arguments.get_raw_commands_by_filter(
            command_arguments.Type.Develop,
            command_arguments.Type.AMQPTarget,
            command_arguments.Type.AMQPKey,
            command_arguments.Type.ConfigurationFilePath
        )

        self.__subprocess = subprocess.Popen(args)

        logging.debug(f'Launch gunicorn proxy server. Port = {self.__rest_proxy_port}')
        event.set()

        self.__subprocess.wait()
