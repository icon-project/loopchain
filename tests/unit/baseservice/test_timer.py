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

import asyncio
import datetime

import pytest
from freezegun import freeze_time

from loopchain.baseservice.timer_service import Timer, OffType

TIMER_KEY = "timer_key"
INVALID_TIMER_KEY = "not_exist_key"
TEST_DURATIONS = [0.1, 0.5, 1, 2]

TICK_INTERVAL = 0.001


class TestTimer:
    @pytest.mark.parametrize("duration", TEST_DURATIONS)
    def test_timeout_after_duration_sec_passed(self, duration):
        timer = Timer(duration=duration)
        assert not timer.is_timeout()

        with freeze_time(datetime.datetime.utcnow() + datetime.timedelta(seconds=duration)):
            assert timer.is_timeout()

    @pytest.mark.parametrize("duration", TEST_DURATIONS)
    def test_remain_time_returns_zero_if_passed_over_duration_sec(self, duration):
        timer = Timer(duration=duration)

        remain_time = timer.remain_time()
        assert 0 < remain_time < duration

        with freeze_time(datetime.datetime.utcnow() + datetime.timedelta(seconds=duration)) as frozen_time:
            frozen_time.tick(TICK_INTERVAL)
            remain_time = timer.remain_time()

            assert remain_time == 0

    @pytest.mark.parametrize("duration", TEST_DURATIONS)
    def test_remain_time_returns_positive_if_not_passed_duration_sec(self, duration):
        timer = Timer(duration=duration)

        remain_time = timer.remain_time()
        assert 0 < remain_time < duration

        with freeze_time(datetime.datetime.utcnow() + datetime.timedelta(seconds=duration)) as frozen_time:
            frozen_time.tick(TICK_INTERVAL)
            remain_time = timer.remain_time()

            assert remain_time == 0

    def test_reset_timer_restores_its_start_time(self):
        duration = 5
        offset = 1
        timer = Timer(duration=duration)

        with freeze_time(datetime.datetime.utcnow() + datetime.timedelta(seconds=duration - offset)) as frozen_time:
            frozen_time.tick(TICK_INTERVAL)
            assert 0 < timer.remain_time() < offset

            timer.reset()
            frozen_time.tick(TICK_INTERVAL)

            assert offset < timer.remain_time() < duration

    def test_is_repeat_returns_false_in_default(self):
        timer = Timer(is_repeat=False)
        assert not timer.is_repeat

    def test_is_repeat_returns_true_with_infinite_repeat_timeout(self):
        timer = Timer(is_repeat=True, repeat_timeout=0)
        assert timer.is_repeat

    def test_is_repeat_returns_true_until_repeat_timeout(self):
        duration = 2
        repeat_timeout = 5

        timer = Timer(duration=duration,
                      is_repeat=True,
                      repeat_timeout=repeat_timeout)

        # Timer repeats unless the timer does not reach to repeat_timeout
        for sec in range(repeat_timeout):
            with freeze_time(datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(seconds=sec)):
                assert timer.is_repeat

        # But after passed repeat_timeout sec, the timer does not repeat itself
        with freeze_time(datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(seconds=repeat_timeout)):
            assert not timer.is_repeat

    @pytest.mark.skip(msg="Timer.on do nothing!!!")
    def test_timer_on(self):
        timer = Timer()
        timer.on()

    def test_timer_off_triggers_blocking_func(self, mocker):
        blocking_callback = mocker.MagicMock()

        timer = Timer(callback=blocking_callback)
        assert not blocking_callback.called

        timer.off(OffType.time_out)
        assert blocking_callback.called

    def test_timer_off_triggers_coroutine_func(self, mocker):
        coro_call_checker = mocker.MagicMock()

        async def coro_callback(**kwargs):
            coro_call_checker()

        timer = Timer(callback=coro_callback)

        timer.off(OffType.time_out)
        asyncio.get_event_loop().run_until_complete(asyncio.sleep(0))  # Give a chance for coroutine to run

        assert coro_call_checker.called

    def test_timer_off_and_exception_in_blocking_func_does_not_break_process(self, mocker):
        blocking_callback = mocker.MagicMock()
        blocking_callback.side_effect = RuntimeError("Call is back!!")
        timer = Timer(callback=blocking_callback)
        assert not blocking_callback.called

        timer.off(OffType.time_out)
        assert blocking_callback.called

    def test_timer_off_and_exception_in_coroutine_func_does_not_break_process(self, mocker):
        coro_call_checker = mocker.MagicMock()
        coro_call_checker.side_effect = RuntimeError("Call is back!!")

        async def coro_callback(**kwargs):
            coro_call_checker()

        timer = Timer(callback=coro_callback)

        timer.off(OffType.time_out)
        asyncio.get_event_loop().run_until_complete(asyncio.sleep(0))  # Give a chance for coroutine to run

        assert coro_call_checker.called


