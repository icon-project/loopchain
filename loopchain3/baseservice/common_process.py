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
"""base class for sub processes"""

import logging
import multiprocessing
import time
import threading
from abc import abstractmethod

from loopchain import configure as conf


class CommonProcess:
    """BaseClass for MultiProcess Architecture.
    It has same interface name as CommonThread for easy conversion.
    """

    def __init__(self):
        self.__conn = None
        self.__run_process = None
        self.__join_thread = None

    def is_run(self):
        return self.__run_process.is_alive()

    def start(self):
        parent_conn, child_conn = multiprocessing.Pipe()
        event = multiprocessing.Event()

        self.__conn = parent_conn
        self.__run_process = multiprocessing.Process(target=self.run, args=(child_conn, event))
        self.__run_process.start()

        # To avoid defunct process
        self.__join_thread = threading.Thread(target=self.wait)
        self.__join_thread.start()

        # If no sleep then CommonProcess will be terminated with exitcode SIGSEGV.
        # It may be python bug/
        time.sleep(conf.SLEEP_SECONDS_FOR_INIT_COMMON_PROCESS)
        event.wait()

    def stop(self):
        logging.debug("try stop process...")

        # When the process starts, the value setting through the method does not work. (Differences from threads)
        #  Communication is possible only through process_queue.
        self.send_to_process(("quit", None))

    def terminate(self):
        logging.debug("try terminate process...")
        self.__run_process.terminate()

    def wait(self):
        logging.debug("try wait process...")
        self.__run_process.join()
        logging.debug(f"process ends exitcode({self.__run_process.exitcode})...")

    def send_to_process(self, job):
        self.__conn.send(job)

    def recv_from_process(self):
        """process 에서 pipe 를 통해서 값을 구한다.

        :return:
        """
        try:
            return self.__conn.recv()
        except EOFError:
            logging.error("fail recv from process!")
            return None

    @abstractmethod
    def run(self, child_conn, event: multiprocessing.Event):
        """멀티 프로세스로 동작할 루프를 정의한다.
        sample 구현을 참고한다.
        """

        event.set()
        # # sample 구현
        # command = None
        # while command != "quit":
        #     command, param = conn.recv()  # Pipe 에 내용이 들어올 때까지 여기서 대기 된다. 따라서 Sleep 이 필요 없다.
        pass
