"""Recovery module"""

import asyncio
import logging
import re
from typing import List, Dict, Any, Union

from loopchain import configure as conf
from loopchain.baseservice.rest_client import RestClient, RestMethod


class Recovery:
    _highest_block_height: int = 0

    def __init__(self, channel: str, last_block_height: int):
        self._channel_name: str = channel
        self._last_block_height: int = last_block_height

        self._min_quorum: int = 0
        self._endpoints: List[str] = []

    def set_target_list(self, target_list: List[str]) -> None:
        regex = re.compile(r":([0-9]{2,5})$")
        for target in target_list:
            port = regex.search(target).group(1)
            new_port = f"{int(port) + conf.PORT_DIFF_REST_SERVICE_CONTAINER}"
            endpoint = target.replace(port, new_port)
            self._endpoints.append(endpoint)

        fault: int = int((len(self._endpoints) - 1) / 3)
        self._min_quorum: int = 2 * fault + 1

    async def _fetch_recovery(self, endpoint: str) -> Dict[str, Union[bool, int]]:
        client = RestClient(self._channel_name, endpoint)
        response: Dict[str, Any] = await client.call_async(RestMethod.Status)

        result = response.get("recovery", {}).copy()
        result.update({"state": response.get("state", None)})

        if result.get("mode", False):
            if result.get("state") == "Recovery":
                block_height = response.get("block_height", 0)
            else:
                block_height = result.get("highest_block_height", 0)

            result.update({"block_height": block_height})
        else:
            result.update({"main_block_height": response.get("block_height", 0)})

        logging.debug(f"result: {result}")
        return result

    async def fill_quorum(self) -> None:
        """Loop target list, check node quorum which is greater than 2f + 1 in recovery_mode

        :return: None
        """

        while True:
            Recovery._highest_block_height = 0
            main_highest_block_height = 0
            recovery_quorum = 0

            results = await asyncio.gather(*[self._fetch_recovery(endpoint) for endpoint in self._endpoints],
                                           return_exceptions=True)

            # to filter exceptions
            results = (result for result in results if isinstance(result, dict))
            for result in results:
                if result.get("mode", False):
                    Recovery._highest_block_height = max(Recovery._highest_block_height, result.get("block_height", 0))
                    recovery_quorum += 1
                else:
                    main_highest_block_height = max(main_highest_block_height, result.get("main_block_height", 0))
                    if main_highest_block_height > self._last_block_height + conf.RELEASE_RECOVERY_BLOCK_COUNT:
                        logging.info(f"release recovery mode: "
                                     f"my_block_height({self._last_block_height}), "
                                     f"highest_block_height({main_highest_block_height})")
                        conf.RECOVERY_MODE = False
                        return

            logging.debug(f"highest_block_height: {Recovery._highest_block_height}")
            logging.info(f"recovery_mode quorum : {recovery_quorum}")
            if recovery_quorum > self._min_quorum:
                return

            await asyncio.sleep(conf.RECOVERY_CHECK_INTERVAL)

    @classmethod
    def get_highest_block_height(cls) -> int:
        return cls._highest_block_height

    @classmethod
    def release_block_height(cls) -> int:
        return cls._highest_block_height + conf.RELEASE_RECOVERY_BLOCK_COUNT
