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
"""run stand alone process as a subprocess"""

import logging
import subprocess
import setproctitle


class CommonSubprocess:
    """run stand alone process as a subprocess
    """
    def __init__(self, process_args):
        logging.debug("common_subprocess:CommonSubprocess init")
        self.__process_args = process_args
        self.__is_run = False
        self.__subprocess: subprocess.Popen = None
        self.start()

    def __del__(self):
        self.stop()

    def is_run(self):
        return self.__is_run

    @staticmethod
    def set_proctitle(title):
        setproctitle.setproctitle(title)

    def start(self):
        """start subprocess
        """
        logging.debug("common_subprocess:CommonSubprocess start")
        if not self.__is_run:
            logging.debug("common_subprocess:CommonSubprocess run process")
            self.__subprocess = subprocess.Popen(self.__process_args)
            self.__is_run = True

    def stop(self):
        """stop subprocess
        """
        logging.debug("common_subprocess:CommonSubprocess stop")
        if self.__is_run:
            self.__subprocess.terminate()
            self.__is_run = False
            self.wait()

    def wait(self):
        """wait subprocess
        """
        logging.debug("common_subprocess:CommonSubprocess wait")
        self.__subprocess.wait()
