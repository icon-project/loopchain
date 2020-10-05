"""Recovery module"""

import asyncio
import logging
import re
from typing import List, Dict, Any

from loopchain import configure as conf
from loopchain.baseservice.rest_client import RestClient, RestMethod


class Recovery:
    _highest_block_height: int = 0

    def __init__(self, channel: str):
        self._channel_name: str = channel
        self.min_quorum: int = 0
        self.endpoints: List[str] = []

    def set_target_list(self, target_list: List[str]) -> None:
        regex = re.compile(r":([0-9]{2,5})$")
        for target in target_list:
            port = regex.search(target).group(1)
            new_port = f"{int(port) + conf.PORT_DIFF_REST_SERVICE_CONTAINER}"
            endpoint = target.replace(port, new_port)
            self.endpoints.append(endpoint)

        fault: int = int((len(self.endpoints) - 1) / 3)
        self.min_quorum: int = fault * 2 + 1

    async def _fetch_recovery(self, endpoint: str) -> bool:
        client = RestClient(self._channel_name, endpoint)
        response: Dict[str, Any] = await client.call_async(RestMethod.Status)

        recovery = response.get("recovery", {})
        recovery_mode = recovery.get("mode", False)
        if recovery_mode:
            if response.get("state") == "RecoveryMode":
                block_height = response.get("block_height", 0)
            else:
                block_height = recovery.get("highest_block_height", 0)

            Recovery._highest_block_height = max(Recovery._highest_block_height, block_height)
            logging.debug(f"highest_block_height: {Recovery._highest_block_height}")

        return recovery_mode

    async def fill_quorum(self) -> None:
        """Loop target list, check node count which is greater than 2f in recovery_mode

        :return: None
        """

        while True:
            results = await asyncio.gather(*[self._fetch_recovery(endpoint) for endpoint in self.endpoints],
                                           return_exceptions=True)

            # to filter exceptions
            results = [result for result in results if isinstance(result, bool)]
            recovery_quorum = results.count(True)

            logging.info(f"recovery_mode quorum : {recovery_quorum}")
            if recovery_quorum >= self.min_quorum:
                await asyncio.sleep(conf.RECOVERY_CHECK_INTERVAL + 1)
                return

            await asyncio.sleep(conf.RECOVERY_CHECK_INTERVAL)

    @classmethod
    def get_highest_block_height(cls) -> int:
        return cls._highest_block_height

    @classmethod
    def release_block_height(cls) -> int:
        return cls._highest_block_height + conf.RELEASE_RECOVERY_BLOCK_COUNT
