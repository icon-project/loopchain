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
"""A management class for generation block ."""

import logging
import queue
import threading
import time

import loopchain.configure as conf
from loopchain.baseservice import CommonThread


class BlockGenerationScheduler(CommonThread):
    def __init__(self, channel):
        CommonThread.__init__(self)
        self.__channel_name = channel
        self.__schedule_queue = queue.Queue()

    def add_schedule(self, schedule):
        self.__schedule_queue.put(schedule)

    def get_schedule(self):
        return self.__schedule_queue.get()

    def is_empty(self):
        return self.__schedule_queue.empty()

    def __consensus_round(self, callback_function, callback_kwargs):
        while True:
            result = callback_function(**callback_kwargs)
            if result is True:
                break

    def run(self, event: threading.Event):
        logging.info(f"channel({self.__channel_name}) BlockGenerationScheduler thread Start.")
        event.set()

        while self.is_run():
            if not self.__schedule_queue.empty():
                schedule = self.__schedule_queue.get()
                self.__consensus_round(schedule.callback, schedule.kwargs)
            else:
                time.sleep(conf.SLEEP_SECONDS_IN_SERVICE_LOOP)

        logging.info(f"channel({self.__channel_name}) BlockGenerationScheduler thread Ended.")
