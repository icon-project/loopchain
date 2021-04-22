import asyncio
import time

from ...utils import logger
from ...blockchain.types import ExternalAddress


def now():
    return int(time.monotonic())  # unit: second


DOS_OVERFLOW_TX_KEY = "overflow_tx"
DOS_TX_FROM_DENYLIST_KEY = "tx_from_denylist"


class Item:
    _TX_FROM_CHECK_BOUNDARY_TIME = 5  # 5s
    _GUARD_THRESHOLD = 100
    _TX_FROM_BLOCK_DURATION = 120  # 120s

    def __init__(self):
        self._count = 0
        self._expired_time = 0
        self._blocked = False

    @classmethod
    def init(cls, boundary_time: int, guard_threshold: int, block_duration: int):
        cls._TX_FROM_CHECK_BOUNDARY_TIME = boundary_time
        cls._GUARD_THRESHOLD = guard_threshold
        cls._TX_FROM_BLOCK_DURATION = block_duration

    @property
    def count(self) -> int:
        return self._count

    @property
    def expired_time(self) -> int:
        return self._expired_time

    @property
    def is_blocked(self) -> bool:
        return self._blocked

    def increment_count(self) -> bool:
        """
        :return: blocked state is changed or not
        """
        cur_time = now()

        if cur_time > self._expired_time:
            self._count = 0
        if self._count == 0:
            self._expired_time = cur_time + self._TX_FROM_CHECK_BOUNDARY_TIME

        self._count += 1
        blocked = self._count > self._GUARD_THRESHOLD

        if blocked:
            self._expired_time = cur_time + self._TX_FROM_BLOCK_DURATION
        if blocked != self._blocked:
            self._blocked = blocked
            return True

        return False

    def __str__(self) -> str:
        return (
            f"count={self._count} "
            f"blocked={self._blocked} "
            f"expired_time={self._expired_time}"
        )


class DoSGuard:
    def __init__(self, block_mgr, ch_svc):
        self._block_mgr = block_mgr
        self._ch_svc = ch_svc
        self._is_run = True

        self._is_update_overflow_tx = False
        self._is_update_denylist = False

        self._last_overflow_tx: bool = False
        self._denylist = set()
        self._statistics = {}

        self._count_to_resume_accept = 0
        self._count_to_start_reject = 0
        self._timer_interval = 5

        logger.info("[DoSGuard] init")

    def open(
            self,
            loop,
            count_to_resume_accept: int,
            count_to_start_reject: int,
            boundary_time: int,
            guard_threshold: int,
            block_duration: int,
            timer_interval: int,
    ):
        logger.info(f"[DoSGuard] open, "
                    f"{count_to_resume_accept}, {count_to_start_reject}, "
                    f"{boundary_time}, {guard_threshold}, {block_duration}, {timer_interval}")
        self._count_to_resume_accept = count_to_resume_accept
        self._count_to_start_reject = count_to_start_reject
        self._timer_interval = timer_interval
        Item.init(boundary_time, guard_threshold, block_duration)

        if loop:
            loop.create_task(self._main_timer())

    def close(self):
        self._is_run = False
        logger.info("[DoSGuard] close")

    async def _main_timer(self):
        while self._is_run:
            await asyncio.sleep(self._timer_interval)
            self._check_overflow_tx()
            self._check_denylist()
            await self._upload_dos_properties()
            logger.info("[DoSGuard] _main_timer")
        logger.info("[DoSGuard] _main_timer close")

    def _check_overflow_tx(self):
        tx_pool_length: int = self._block_mgr.get_count_of_unconfirmed_tx()
        logger.debug(f"[DoSGuard] _check_overflow_tx {tx_pool_length}")
        if tx_pool_length <= self._count_to_resume_accept:
            overflow_tx = False
        elif tx_pool_length >= self._count_to_start_reject:
            overflow_tx = True
        else:
            overflow_tx = self._last_overflow_tx

        if self._last_overflow_tx != overflow_tx:
            self._is_update_overflow_tx = True
            self._last_overflow_tx = overflow_tx
            logger.info("[DoSGuard] is_update_overflow_tx True")

    def _check_denylist(self):
        cur_time: int = now()
        expired_addresses = []

        for _from in self._denylist:
            item = self._statistics.get(_from)
            if item is None:
                logger.warning(f"DoSItem for {_from} is None")
                continue

            if item and cur_time > item.expired_time:
                expired_addresses.append(_from)
                del self._statistics[_from]

        if len(expired_addresses):
            self._is_update_denylist = True
            for address in expired_addresses:
                self._denylist.remove(address)

    async def _upload_dos_properties(self):
        dos_properties: dict = {}
        if self._is_update_overflow_tx:
            self._is_update_overflow_tx = False
            dos_properties[DOS_OVERFLOW_TX_KEY] = self._last_overflow_tx
        if self._is_update_denylist:
            self._is_update_denylist = False
            dos_properties[DOS_TX_FROM_DENYLIST_KEY] = self._denylist

        if dos_properties:
            logger.info(f"[DoSGuard] _upload_dos_properties: {dos_properties}")
            await self._ch_svc.inner_service.update_dos_properties(dos_properties)

    def invoke(self, tx) -> bool:
        _from = tx.from_address.hex_hx()
        from_tx_statistics: dict = self._statistics

        item = from_tx_statistics.get(_from)
        if item is None:
            item = Item()
            from_tx_statistics[_from] = item
            logger.info(f"[DoSGuard] len(from_tx_statistics)={len(from_tx_statistics)}")

        # if the blocked state of the item is changed
        if item.increment_count():
            self._is_update_denylist = True
            if item.is_blocked:
                self._denylist.add(_from)
            else:
                self._denylist.remove(_from)
            logger.info(f"[DosGuard] from={_from} {item}")
        return item.is_blocked
