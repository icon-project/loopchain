import pytest

from loopchain.baseservice.timer_service import TimerService


@pytest.fixture
def timer_service():
    ts = TimerService()
    ts.start()

    yield ts

    ts.stop()
