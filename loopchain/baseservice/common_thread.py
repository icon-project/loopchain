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
"""base class for multi thread """

import logging
import threading
from abc import abstractmethod


class CommonThread:
    """Thread 로 동작하는 클래스의 공통 요소 분리
    코드 내에서 쓰레드로 동작하는 부분을 명시적으로 구분하기 쉽게 한다.
    """

    def __init__(self):
        logging.debug("common_thread:CommonThread init")
        self.__is_run = False
        self.__run_thread = None

    def is_run(self):
        return self.__is_run

    def start(self):
        """쓰레드를 시작한다.
        상속받아서 override 하는 경우 반드시 CommonThread.start(self) 를 호출하여야 한다.
        """
        logging.debug("CommonThread start")

        event = threading.Event()

        self.__is_run = True
        self.__run_thread = threading.Thread(target=self.run, args=(event, ))
        self.__run_thread.daemon = True
        self.__run_thread.start()

        event.wait()

    def stop(self):
        """쓰레드를 중지한다.
        상속받아서 override 하는 경우 반드시 CommonThread.stop(self) 을 호출하여야 한다.
        """
        # logging.debug("try stop thread...")
        self.__is_run = False

    def wait(self):
        """쓰레드 종료를 기다린다.
        """
        logging.debug("common_thread:CommonThread wait thread...")
        self.__run_thread.join()

    @abstractmethod
    def run(self, event: threading.Event):
        """쓰레드로 동작할 루프를 정의한다.
        sample 구현을 참고 한다.
        """

        event.set()
        # # sample 구현
        # while self.is_run():
        #     time.sleep(conf.SLEEP_SECONDS_IN_SERVICE_LOOP)
        pass
