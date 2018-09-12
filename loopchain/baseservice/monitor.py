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
"""Process Monitoring Singleton Thread. Check appended process is alive and restart it."""

import logging
import threading
import time

import loopchain.utils as util
from loopchain import configure as conf
from loopchain.baseservice import CommonThread
from loopchain.components import SingletonMetaClass


class Monitor(CommonThread, metaclass=SingletonMetaClass):

    def __init__(self):
        CommonThread.__init__(self)
        util.logger.spam(f"monitor:Monitor init")
        self.__processes = {}  # {channel_name: [process_list]}
        self.__confirmation_monitoring_stop = False

    def append(self, channel, process):
        if channel not in self.__processes:
            self.__processes[channel] = []

        self.__processes[channel].append(process)

    def start(self):
        self.__confirmation_monitoring_stop = False
        super().start()

    def stop(self):
        CommonThread.stop(self)
        while not self.__confirmation_monitoring_stop:
            time.sleep(conf.INTERVAL_SECONDS_PROCESS_MONITORING)

    def stop_wait_monitoring(self):
        self.__confirmation_monitoring_stop = True

    def remove_channel_process(self, channel):
        util.logger.spam(f"monitor:remove_channel_process restarting channel({channel} in {self.__processes.keys()})")
        try:
            self.__processes.pop(channel)
        except KeyError as e:
            logging.warning(f"the channel({channel}) may be already restarting "
                            f"or does not exist in the channel list ({e})")

    def run(self, event: threading.Event):
        event.set()

        try:
            while self.is_run():
                time.sleep(conf.INTERVAL_SECONDS_PROCESS_MONITORING)
                # util.logger.spam(f"process monitoring loop")

                for channel in list(self.__processes):
                    for process in list(self.__processes[channel]):
                        if not process.is_alive():
                            logging.warning(f"monitor:run process({process.process_name}) is not alive, try re_start!")
                            process.re_start()
                            self.__processes[channel].remove(process)
                        else:
                            util.logger.spam(f"monitor:run process({process.process_name}) is alive...")
                            pass
        finally:
            self.__confirmation_monitoring_stop = True
