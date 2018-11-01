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
"""loopchain timer service."""

import asyncio

from loopchain.baseservice import CommonThread
from loopchain.blockchain import *


class OffType(Enum):
    """enum class of reason to turn off timer"""

    normal = 0
    time_out = 1


class Timer:
    """timer object"""

    def __init__(self, **kwargs):
        """initial function

        :param target:      target of timer
        :param duration:    duration for checking timeout
        :param start_time:  start time of timer
        :param is_repeat:   if true, the timer runs repeatedly
        :param callback:    callback function after timeout or normal case
        :param kwargs:      parameters for callback function
        """
        self.__target = kwargs.get("target")
        self.__duration = kwargs.get("duration")
        self.__start_time = time.time()
        self.__is_repeat = kwargs.get("is_repeat", False)
        self.__callback = kwargs.get("callback", None)
        self.__kwargs = kwargs.get("callback_kwargs", {})

    @property
    def target(self):
        return self.__target

    @property
    def is_repeat(self):
        return self.__is_repeat

    def is_timeout(self):
        if time.time() - self.__start_time < self.__duration:
            return False

        util.logger.spam(f'gap: {time.time() - self.__start_time}')
        return True

    def reset(self):
        self.__start_time = time.time()
        util.logger.spam(f"reset_timer: {self.__target}")

    def remain_time(self):
        end_time = self.__start_time + self.__duration
        remain = end_time - time.time()
        return remain if remain > 0 else 0

    def on(self):
        logging.debug(f'TIMER IS ON ({self.__target})')

    def off(self, off_type):
        """turn off timer by type

        :param off_type: type of reason to turn off timer
        """
        if off_type is OffType.time_out:
            logging.debug(f'timer({self.__target}) is turned off by timeout')
            self.__callback(**self.__kwargs)

    def __repr__(self):
        return f"{self.__callback}, {self.remain_time()}"


class TimerService(CommonThread):
    """timer service"""

    TIMER_KEY_BLOCK_HEIGHT_SYNC = "TIMER_KEY_BLOCK_HEIGHT_SYNC"
    TIMER_KEY_ADD_TX = "TIMER_KEY_ADD_TX"
    TIMER_KEY_SUBSCRIBE = "TIMER_KEY_SUBSCRIBE"
    TIMER_KEY_CONNECT_PEER = "TIMER_KEY_CONNECT_PEER"
    TIMER_KEY_RS_HEARTBEAT = "TIMER_KEY_RS_HEARTBEAT"
    TIMER_KEY_SHUTDOWN_WHEN_FAIL_SUBSCRIBE = "TIMER_KEY_SHUTDOWN_WHEN_FAIL_SUBSCRIBE"
    TIMER_KEY_BLOCK_GENERATE = "TIMER_KEY_BLOCK_GENERATE"

    def __init__(self):
        CommonThread.__init__(self)
        self.__timer_list = {}
        self.__loop: asyncio.BaseEventLoop = asyncio.new_event_loop()

    def get_event_loop(self):
        return self.__loop

    @property
    def timer_list(self):
        return self.__timer_list

    def add_timer(self, key, timer):
        """add timer to self.__timer_list

        :param key: key
        :param timer: timer object
        :return:
        """
        try:
            timer = self.__timer_list[key]
        except KeyError:  # new timer
            self.__timer_list[key] = timer
            asyncio.run_coroutine_threadsafe(self.__run(key, timer), self.__loop)
            timer.on()
        else:  # old timer
            timer.reset()

    def remove_timer(self, key):
        """remove timer from self.__timer_list

        :param key: key
        :return:
        """
        if key in self.__timer_list:
            del self.__timer_list[key]
        else:
            logging.warning(f'({key}) is not in timer list.')

    def get_timer(self, key):
        """get a timer by key

        :param key: key
        :return: a timer by key
        """
        if key in self.__timer_list.keys():
            return self.__timer_list[key]
        else:
            logging.debug(f'get_timer:There is no value by this key: {key}')
            return None

    def reset_timer(self, key):
        """reset the start time of the timer (to delay the callback)

        :param key: key
        :return:
        """
        if key in self.__timer_list.keys():
            self.__timer_list[key].reset()
        else:
            logging.warning(f'reset_timer:There is no value by this key: {key}')

    def restart_timer(self, key):
        """restart the timer when timer is timeout (off the timer to run callback)

        :param key: key
        :return:
        """
        if key in self.__timer_list.keys():
            timer = self.__timer_list[key]
            timer.off(OffType.time_out)
            timer.reset()
            asyncio.run_coroutine_threadsafe(self.__run(key, timer), self.__loop)
        else:
            logging.warning(f"restart_timer:There is no value by this key: {key}")

    def stop_timer(self, key, off_type=OffType.normal):
        """stop timer

        :param key: key
        :param off_type: type of reason to turn off timer
        :return:
        """
        if key in list(self.__timer_list):
            timer = self.__timer_list[key]
            self.remove_timer(key)
            timer.off(off_type)

            logging.debug(f"TIMER IS STOP ({key})")
            util.logger.spam(f"remain timers after stop_timer: {self.__timer_list.keys()}")
        else:
            logging.warning(f'stop_timer:There is no value by this key: {key}')

    def stop(self):
        super().stop()

        self.__loop.call_soon_threadsafe(self.__loop.stop)

    def run(self, e: threading.Event):
        e.set()

        asyncio.set_event_loop(self.__loop)
        self.__loop.run_forever()

    async def __run(self, key, timer: Timer):
        while not timer.is_timeout():
            util.logger.spam(f"sleep {timer.remain_time()}, {key}")
            await asyncio.sleep(timer.remain_time())

        if key not in self.__timer_list.keys():
            pass
        elif timer.is_repeat:
            self.restart_timer(key)
        else:
            self.stop_timer(key, OffType.time_out)
