import asyncio
import enum
import time

from loopchain import configure as conf
from ...utils import logger


def now():
    return int(time.monotonic())  # unit: second


class Category(enum.Enum):
    FROM_TX = 0


DOS_OVERFLOW_TX_KEY = "overflow_tx"
DOS_TX_FROM_BLACKLIST_KEY = "tx_from_blacklist"


class DoSGuard:
    def __init__(
            self,
            block_mgr,
            ch_svc,
            loop
    ):
        self._enable: bool = conf.DOS_GUARD_ENABLE
        if not self._enable:
            return

        self._block_mgr = block_mgr
        self._ch_svc = ch_svc
        self._is_run = True

        self._is_update_overflow_tx = False
        self._is_update_blacklist = {c.value: False for c in Category}

        self._last_overflow_tx: bool = False
        self._last_blacklist: dict = {c.value: [] for c in Category}

        self._statistics: dict = {c.value: {} for c in Category}
        self._blacklist_expired: dict = {c.value: {} for c in Category}

        loop.create_task(self._main_timer())
        loop.create_task(self._tx_from_check_boundary_timer())
        logger.info("[DoSGuard] DoSGuard Init")

    def close(self):
        if not self._enable:
            return

        self._is_run = False
        logger.info("[DoSGuard] close")

    async def _main_timer(self):
        while self._is_run:
            await asyncio.sleep(1)
            await self._check_overflow_tx()
            await self._check_tx_from_blacklist()
            await self._upload_dos_properties()
            logger.info("[DoSGuard] _main_timer")
        logger.info("[DoSGuard] _main_timer close")

    async def _tx_from_check_boundary_timer(self):
        while self._is_run:
            await asyncio.sleep(conf.DOS_GUARD_TX_FROM_CHECK_BOUNDARY_TIME)
            await self._tx_from_check_boundary_reset()
            logger.info("[DoSGuard] _tx_from_check_boundary_timer")
        logger.info("[DoSGuard] _tx_from_check_boundary_timer close")

    async def _tx_from_check_boundary_reset(self):
        self._statistics = {c.value: {} for c in Category}

    async def _check_overflow_tx(self):
        tx_pool_length: int = self._block_mgr.get_count_of_unconfirmed_tx()
        logger.debug(f"[DoSGuard] _check_overflow_tx {tx_pool_length}")
        if tx_pool_length <= conf.DOS_GUARD_TX_COUNT_TO_RESUME_ACCEPT:
            overflow_tx = False
        elif tx_pool_length >= conf.DOS_GUARD_TX_COUNT_TO_START_REJECT:
            overflow_tx = True
        else:
            overflow_tx = self._last_overflow_tx

        if self._last_overflow_tx != overflow_tx:
            self._is_update_overflow_tx = True
            self._last_overflow_tx = overflow_tx
            logger.info("[DoSGuard] is_update_overflow_tx True")

    async def _check_tx_from_blacklist(self):
        cur_time: int = now()
        tmp_blacklist: list = [
            k for k, v in self._blacklist_expired[Category.FROM_TX.value].items()
            if v >= cur_time
        ]
        logger.debug(f"[DoSGuard] _check_tx_from_blacklist: {tmp_blacklist}")
        if self._last_blacklist[Category.FROM_TX.value] != tmp_blacklist:
            self._is_update_blacklist[Category.FROM_TX.value] = True
            self._last_blacklist[Category.FROM_TX.value] = tmp_blacklist
            logger.info("[DoSGuard] is_update_blacklist[Category.FROM_TX] True")

    async def _upload_dos_properties(self):
        dos_properties: dict = {}
        if self._is_update_overflow_tx:
            self._is_update_overflow_tx = False
            dos_properties[DOS_OVERFLOW_TX_KEY] = self._last_overflow_tx
        if self._is_update_blacklist[Category.FROM_TX.value]:
            self._is_update_blacklist[Category.FROM_TX.value] = False
            dos_properties[DOS_TX_FROM_BLACKLIST_KEY] = self._last_blacklist[Category.FROM_TX.value]

        if dos_properties:
            logger.info(f"[DoSGuard] _upload_dos_properties: {dos_properties}")
            await self._ch_svc.inner_service.update_dos_properties(dos_properties)

    def commit(self):
        if not self._enable:
            return

        tmp_blacklist: list = [
            k for k, v in self._statistics[Category.FROM_TX.value].items()
            if v >= conf.DOS_GUARD_THRESHOLD
        ]
        logger.debug(f"[DoSGuard] commit: {tmp_blacklist}")

        for addr in tmp_blacklist:
            self._blacklist_expired[Category.FROM_TX.value][addr] = now() + conf.DOS_GUARD_TX_FROM_BLACKLIST_TIME

    def invoke(self, tx) -> bool:
        if not self._enable:
            return True

        _from: str = tx.from_address.hex_hx()

        from_tx_statistics: dict = self._statistics[Category.FROM_TX.value]
        from_tx_statistics[_from] = from_tx_statistics.get(_from, 0) + 1

        if _from in self._last_blacklist[Category.FROM_TX.value]:
            return False

        if from_tx_statistics[_from] >= conf.DOS_GUARD_THRESHOLD:
            return False

        return True
