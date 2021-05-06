import time
import unittest
import os

from loopchain import configure_default as conf
from loopchain.utils.dosguard import dosguard
from loopchain.utils.dosguard.dosguard import DoSGuard, Item, ItemState
from loopchain.blockchain.types import ExternalAddress


_now = 0


def _mock_now() -> int:
    return _now


def _sleep(delta: int):
    global _now
    _now += delta


class TestItem(unittest.TestCase):

    def setUp(self) -> None:
        boundary_time = 2
        reset_time = 8
        guard_threshold = 100
        block_duration = 5

        Item.init(
            boundary_time=boundary_time,
            reset_time=reset_time,
            guard_threshold=guard_threshold,
            block_duration=block_duration)
        assert Item._TX_FROM_CHECK_BOUNDARY_TIME == boundary_time
        assert Item._GUARD_THRESHOLD == guard_threshold
        assert Item._TX_FROM_BLOCK_DURATION == block_duration

        self.guard_threshold = guard_threshold
        self.block_duration = block_duration
        self.reset_time = reset_time

        self.org_now = dosguard.now
        dosguard.now = _mock_now

    def tearDown(self) -> None:
        dosguard.now = self.org_now

    def test_increment_count(self):
        item = Item()

        # Before blocking is enabled
        for i in range(self.guard_threshold):
            ret: ItemState = item.increment_count()
            assert item.count == i + 1
            assert ret == ItemState.NONE
            assert not item.is_blocked

        # Blocking is enabled
        ret: ItemState = item.increment_count()
        assert item.count == self.guard_threshold + 1
        assert ret == ItemState.CHANGED
        assert item.is_blocked

        # Extend the block duration while blocking
        for i in range(10):
            ret: ItemState = item.increment_count()
            assert item.count == self.guard_threshold + i + 2
            assert ret == ItemState.NONE
            assert item.is_blocked

        # Simulate not to send tx for 6s
        _sleep(self.block_duration + 1)

        # Revoke to block
        ret: ItemState = item.increment_count()
        assert item.count == 1
        assert ret == ItemState.CHANGED
        assert not item.is_blocked

        for i in range(10):
            ret: ItemState = item.increment_count()
            assert item.count == i + 2
            assert ret == ItemState.NONE
            assert not item.is_blocked

        # Sleep for 11s to simulate reset
        _sleep(self.reset_time + 1)

        ret: ItemState = item.increment_count()
        assert ret == ItemState.RESET
        assert item.count > 0
        assert not item.is_blocked


class MockTx:
    def __init__(self, address: ExternalAddress):
        self.from_address = address


class TestDosGuard(unittest.TestCase):
    def setUp(self) -> None:
        guard_threshold = conf.DOS_GUARD_THRESHOLD
        block_duration = 5
        timer_interval = 5
        reset_time = 10

        guard = DoSGuard(block_mgr=None, ch_svc=None)
        guard.open(
            loop=None,
            count_to_resume_accept=conf.DOS_GUARD_TX_COUNT_TO_RESUME_ACCEPT,
            count_to_start_reject=conf.DOS_GUARD_TX_COUNT_TO_START_REJECT,
            boundary_time=conf.DOS_GUARD_TX_FROM_CHECK_BOUNDARY_TIME,
            reset_time=reset_time,
            guard_threshold=guard_threshold,
            block_duration=block_duration,
            timer_interval=timer_interval,
        )

        self.guard = guard
        self.reset_time = reset_time
        self.guard_threshold = guard_threshold
        self.block_duration = block_duration

        self.org_now = dosguard.now
        dosguard.now = _mock_now

    def tearDown(self) -> None:
        dosguard.now = self.org_now

    def test_invoke(self):
        guard = self.guard
        value = f"hx{os.urandom(20).hex()}"
        address = ExternalAddress.fromhex_address(value)
        tx = MockTx(address)

        for i in range(self.guard_threshold):
            blocked: bool = guard.invoke(tx)
            assert not blocked
            assert not guard._is_update_denylist
            assert len(guard._denylist) == 0

        # The case when count > guard_threshold
        blocked: bool = guard.invoke(tx)
        assert blocked
        assert guard._is_update_denylist
        assert value in guard._denylist

        # Blocking is expired
        _sleep(self.block_duration + 1)
        guard._check_denylist()
        assert value not in guard._denylist

        blocked: bool = guard.invoke(tx)
        assert not blocked
        assert guard._is_update_denylist
        assert len(guard._denylist) == 0

        # Sleep for reset test
        _sleep(self.reset_time + 1)

        # Case when cur_time - expire_time > reset_time and count > 0 and not blocked
        blocked: bool = guard.invoke(tx)
        assert not blocked
        assert value not in guard._statistics
