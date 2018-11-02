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
"""Test timer service"""
import unittest

import testcase.unittest.test_util as test_util

from loopchain.baseservice.timer_service import *
from loopchain.utils import loggers

loggers.set_preset_type(loggers.PresetType.develop)
loggers.update_preset()


class TestTimerService(unittest.TestCase):

    def setUp(self):
        self.__timer_callback_result = None
        self.__default_consensus_algorithm = conf.CONSENSUS_ALGORITHM
        conf.CONSENSUS_ALGORITHM = conf.ConsensusAlgorithm.lft
        test_util.print_testname(self._testMethodName)

    def tearDown(self):
        conf.CONSENSUS_ALGORITHM = self.__default_consensus_algorithm

    def __timer_callback(self, **kwargs):
        self.__timer_callback_result = kwargs.get("key", None)
        logging.debug(f'timer_callback_result : {self.__timer_callback_result}')

    def test_add_timer(self):
        # GIVEN
        timer_service = TimerService()
        timer_service.start()
        duration = 5
        key1 = 'block_hash_1'
        key2 = 'block_hash_2'

        # WHEN
        timer_service.add_timer(key1, Timer(
            target=key1, duration=duration, callback=self.__timer_callback, callback_kwargs={"key": key1}))
        timer_service.add_timer(key2, Timer(
            target=key2, duration=duration*2, callback=self.__timer_callback, callback_kwargs={"key": key2}))

        # THEN
        timer_count = len(timer_service.timer_list)
        self.assertEqual(timer_count, 2)
        self.assertIsNotNone(timer_service.get_timer(key1))
        self.assertIsNotNone(timer_service.get_timer(key2))
        timer_service.stop()

    def test_remove_timer(self):
        # GIVEN
        timer_service = TimerService()
        timer_service.start()
        duration = 5
        key1 = 'block_hash_1'
        key2 = 'block_hash_2'

        timer_service.add_timer(key1, Timer(
            target=key1, duration=duration, callback=self.__timer_callback, callback_kwargs={"key": key1}))
        timer_service.add_timer(key2, Timer(
            target=key2, duration=duration*2, callback=self.__timer_callback, callback_kwargs={"key": key2}))

        # WHEN
        timer_service.remove_timer(key1)

        # THEN
        timer_count = len(timer_service.timer_list)
        self.assertEqual(timer_count, 1)
        self.assertIsNone(timer_service.get_timer(key1))
        self.assertIsNotNone(timer_service.get_timer(key2))
        timer_service.stop()

    def test_get_timer(self):
        # GIVEN
        timer_service = TimerService()
        timer_service.start()
        duration = 5
        key1 = 'block_hash_1'
        key2 = 'block_hash_2'
        key3 = 'block_hash_3'

        # WHEN
        timer_service.add_timer(key1, Timer(
            target=key1, duration=duration, callback=self.__timer_callback, callback_kwargs={"key": key1}))
        timer_service.add_timer(key2, Timer(
            target=key2, duration=duration*2, callback=self.__timer_callback, callback_kwargs={"key": key2}))

        # THEN
        self.assertEqual(timer_service.get_timer(key1).target, key1)
        self.assertIsNone(timer_service.get_timer(key3))
        timer_service.stop()

    def test_reset_timer(self):
        # GIVEN
        timer_service = TimerService()
        timer_service.start()
        duration = 2
        key1 = 'block_hash_1'

        call_times = 0
        time_to_call = None

        def call_back(**kwargs):
            nonlocal call_times, time_to_call
            call_times += 1
            time_to_call = time.time()
            logging.debug(f"call time({time_to_call}) call_times ({call_times})")

        time_to_add = time.time()
        logging.debug(f"time to add({time_to_add})")
        timer_service.add_timer(key1, Timer(
            target=key1, duration=duration, callback=call_back, callback_kwargs={"key": key1}))

        # WHEN
        reset_interval = 1
        time.sleep(reset_interval)
        timer_service.reset_timer(key1)

        # THEN
        time.sleep(duration * 2)

        time_interval = time_to_call - time_to_add
        logging.debug(f"time interval({time_interval})")

        self.assertGreater(time_interval, duration + reset_interval)
        timer_service.stop()

    def test_stop_timer(self):
        pass

    def test_timeout_by_timeout(self):
        # GIVEN
        timer_service = TimerService()
        timer_service.start()
        duration = 5
        key1 = 'block_hash_1'

        timer_service.add_timer(key1, Timer(
            target=key1, duration=duration, callback=self.__timer_callback, callback_kwargs={"key": key1}))

        # WHEN
        time.sleep(duration+1)

        # THEN
        self.assertIsNotNone(self.__timer_callback_result)

        timer_service.stop()


if __name__ == '__main__':
    unittest.main()
