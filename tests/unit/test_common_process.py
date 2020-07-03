#!/usr/bin/env python
# -*- coding: utf-8 -*-

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
"""Test Common Process"""

import logging
import multiprocessing
import unittest
import threading
import time

from loopchain import configure as conf
from loopchain.baseservice import CommonProcess
from loopchain.baseservice import CommonThread
from loopchain.utils import loggers

loggers.set_preset_type(loggers.PresetType.develop)
loggers.update_preset()


class SampleThread(CommonThread):
    def __init__(self):
        self.__run_times = 0
        self.__var = 0

    def set_var(self, var):
        self.__var = var

    def get_run_times(self):
        return self.__run_times

    def run(self, event: threading.Event):
        event.set()

        while self.is_run():
            time.sleep(conf.SLEEP_SECONDS_IN_SERVICE_LOOP)
            self.__run_times += 1
            logging.debug("SampleThread, I have: " + str(self.__var))


class SampleProcess(CommonProcess):

    def run(self, conn, event: multiprocessing.Event):
        run_times = 0
        command = None

        event.set()

        while command != "quit":
            command, param = conn.recv()  # Queue 에 내용이 들어올 때까지 여기서 대기 된다. 따라서 Sleep 이 필요 없다.
            run_times += 1
            logging.debug("SampleProcess, I got: " + str(param))
        conn.send(run_times)  # Process 의 리턴도 공유된 Queue 를 통해서만 가능하다.


class TestCommonProcess(unittest.TestCase):

    def test_common_process(self):
        sample_process1 = SampleProcess()
        sample_process1.start()
        sample_thread1 = SampleThread()
        sample_thread1.start()

        times = 0
        while times < 2:
            sample_process1.send_to_process(("times", times))
            sample_thread1.set_var(times)
            time.sleep(1)
            times += 1

        sample_process1.stop()
        sample_process1.wait()
        sample_thread1.stop()
        sample_thread1.wait()

        process_run_times = sample_process1.recv_from_process()
        thread_run_times = sample_thread1.get_run_times()

        logging.debug("SampleThread Run Times: " + str(thread_run_times))
        logging.debug("SampleProcess Run Times: " + str(process_run_times))

        self.assertGreaterEqual(thread_run_times, process_run_times, "Fail Run CommonProcess")


if __name__ == '__main__':
    unittest.main()
