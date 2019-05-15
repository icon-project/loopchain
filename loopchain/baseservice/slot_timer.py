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

import loopchain.utils as util
from loopchain.baseservice import TimerService, Timer


class SlotTimer:
    """Slot Timer"""

    def __init__(self, timer_key, duration, timer_service: TimerService, callback, callback_lock: asyncio.Lock, loop):
        self.__slot = 0
        self.__delayed = True
        self.__timer_key = timer_key
        self.__timer_service = timer_service
        self.__duration = duration
        self.__callback = callback
        self.__callback_lock = callback_lock
        self.__loop = loop
        self.is_running = False

    def start(self, is_run_at_start=True):
        self.is_running = True
        self.__timer_service.add_timer(
            self.__timer_key,
            Timer(
                target=self.__timer_key,
                duration=self.__duration,
                is_repeat=True,
                is_run_at_start=is_run_at_start,
                callback=self.__timer_callback
            )
        )

    def __timer_callback(self):
        util.logger.spam(f"__timer_callback slot({self.__slot}) delayed({self.__delayed})")
        self.__slot += 1
        if self.__delayed:
            self.__delayed = False
            self.call()
        elif self.__slot > 0:
            if not self.__callback_lock.locked():
                util.logger.warning(f"consensus timer loop broken slot({self.__slot}) delayed({self.__delayed})")
                self.call()

    def __add_task(self):
        if not self.is_running:
            util.logger.warning(f"SlotTimer is not running. slot({self.__slot}) delayed({self.__delayed})")
            return
        self.__loop.create_task(self.__callback())

    def call(self):
        util.logger.spam(f"call slot({self.__slot}) delayed({self.__delayed})")

        if self.__slot > 0:
            self.__slot -= 1
            self.__add_task()
        else:
            self.__delayed = True

    def call_instantly(self):
        self.__add_task()

    def stop(self):
        self.is_running = False
        if self.__timer_key in self.__timer_service.timer_list:
            self.__timer_service.stop_timer(self.__timer_key)

        async def _clean_slot():
            self.__slot = 0
            self.__delayed = True

        self.__loop.create_task(_clean_slot())
