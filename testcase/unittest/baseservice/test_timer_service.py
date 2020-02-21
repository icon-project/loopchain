import asyncio

import pytest

from loopchain.baseservice.timer_service import Timer, TimerService, OffType


TIMER_KEY = "timer_key"
INVALID_TIMER_KEY = "not_exist_key"
TEST_DURATIONS = [0.1, 0.5, 1, 2]

TICK_INTERVAL = 0.001


class TestTimerService:
    def test_add_timer_adds_timer_key(self, timer_service: TimerService):
        timer = Timer(duration=1)

        timer_service.add_timer(TIMER_KEY, timer)
        assert len(timer_service.timer_list) == 1
        assert timer_service.get_timer(TIMER_KEY)

    def test_add_timer_with_is_run_at_start(self, timer_service: TimerService, mocker):
        timer = Timer(duration=1, is_run_at_start=True)

        mock_run = mocker.MagicMock()
        mock_run_immediate = mocker.MagicMock()
        timer_service._TimerService__run = mock_run
        timer_service._TimerService__run_immediate = mock_run_immediate

        mocker.patch.object(asyncio, "run_coroutine_threadsafe")
        timer_service.add_timer(TIMER_KEY, timer)
        assert mock_run_immediate.called
        assert not mock_run.called

    def test_add_timer_without_is_run_at_start(self, timer_service: TimerService, mocker):
        timer = Timer(duration=1)

        mock_run = mocker.MagicMock()
        mock_run_immediate = mocker.MagicMock()
        timer_service._TimerService__run = mock_run
        timer_service._TimerService__run_immediate = mock_run_immediate

        mocker.patch.object(asyncio, "run_coroutine_threadsafe")
        timer_service.add_timer(TIMER_KEY, timer)
        assert not mock_run_immediate.called
        assert mock_run.called

    def test_add_timer_convenient_adds_timer_key(self, timer_service: TimerService):
        assert len(timer_service.timer_list) == 0

        timer_service.add_timer_convenient(TIMER_KEY, duration=1)
        assert len(timer_service.timer_list) == 1

    def test_add_timer_convenient_with_duplicated_timer_key(self, timer_service: TimerService):
        assert len(timer_service.timer_list) == 0

        timer_service.add_timer_convenient(TIMER_KEY, duration=1)
        assert len(timer_service.timer_list) == 1

        assert TIMER_KEY in timer_service.timer_list
        timer_service.add_timer_convenient(TIMER_KEY, duration=2)
        assert len(timer_service.timer_list) == 1

    def test_remove_timer_deletes_timer_key(self, timer_service: TimerService):
        timer = Timer(duration=1)
        timer_service.add_timer(TIMER_KEY, timer)

        timer_service.remove_timer(TIMER_KEY)
        assert len(timer_service.timer_list) == 0
        assert not timer_service.get_timer(TIMER_KEY)

    def test_remove_timer_with_invalid_key(self, timer_service: TimerService):
        timer = Timer(duration=1)
        timer_service.add_timer(TIMER_KEY, timer)

        assert not timer_service.remove_timer(INVALID_TIMER_KEY)
        assert TIMER_KEY in timer_service.timer_list

    def test_reset_timer_calls_timer_reset(self, timer_service: TimerService, mocker):
        timer = Timer(duration=1)
        mock_timer_reset = mocker.MagicMock()
        timer.reset = mock_timer_reset
        timer_service.add_timer(TIMER_KEY, timer)

        timer_service.reset_timer(TIMER_KEY)
        assert mock_timer_reset.called

    def test_reset_timer_with_invalid_key(self, timer_service: TimerService, mocker):
        timer = Timer(duration=1)
        mock_timer_reset = mocker.MagicMock()
        timer.reset = mock_timer_reset
        timer_service.add_timer(TIMER_KEY, timer)

        timer_service.reset_timer(INVALID_TIMER_KEY)
        assert not mock_timer_reset.called

    def test_restart_timer_turnoff_timer_and_reset(self, timer_service: TimerService, mocker):
        mock_timer_off = mocker.MagicMock()
        mock_timer_reset = mocker.MagicMock()

        timer = Timer(duration=1)
        timer.off = mock_timer_off
        timer.reset = mock_timer_reset

        timer_service.add_timer(TIMER_KEY, timer)
        timer_service.restart_timer(TIMER_KEY)

        assert mock_timer_off.called
        assert mock_timer_reset.called

    def test_restart_timer_with_invalid_key(self, timer_service: TimerService, mocker):
        mock_timer_off = mocker.MagicMock()
        mock_timer_reset = mocker.MagicMock()

        timer = Timer(duration=1)
        timer.off = mock_timer_off
        timer.reset = mock_timer_reset

        timer_service.add_timer(TIMER_KEY, timer)
        timer_service.restart_timer(INVALID_TIMER_KEY)

        assert not mock_timer_off.called
        assert not mock_timer_reset.called

    def test_stop_timer_calls_timer_off_and_remove(self, timer_service: TimerService, mocker):
        mock_timer_off = mocker.MagicMock()

        timer = Timer(duration=1)
        timer.off = mock_timer_off

        timer_service.add_timer(TIMER_KEY, timer)
        assert TIMER_KEY in timer_service.timer_list

        timer_service.stop_timer(TIMER_KEY, OffType.normal)
        assert TIMER_KEY not in timer_service.timer_list
        assert mock_timer_off.called

    def test_stop_timer_with_invalid_key(self, timer_service: TimerService, mocker):
        mock_timer_off = mocker.MagicMock()

        timer = Timer(duration=1)
        timer.off = mock_timer_off

        timer_service.add_timer(TIMER_KEY, timer)
        assert TIMER_KEY in timer_service.timer_list

        timer_service.stop_timer(INVALID_TIMER_KEY, OffType.normal)
        assert TIMER_KEY in timer_service.timer_list
        assert not mock_timer_off.called

    def test_clean(self, timer_service: TimerService):
        timer = Timer(duration=1)
        timer_service.add_timer(TIMER_KEY, timer)
        assert len(timer_service.timer_list) == 1

        timer_service.clean()
        assert not timer_service.timer_list
