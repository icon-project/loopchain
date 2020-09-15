"""Recovery mode"""

import asyncio
import logging
import re
from typing import List, Dict, Any

import time

from loopchain.baseservice.rest_client import RestClient, RestMethod


class Recovery:
    def __init__(self, channel: str):
        self.waiting_sec: int = 2
        self._channel_name: str = channel
        self.recovery_quorum: int = 0
        self.min_quorum: int = 0
        self.endpoints: List[str] = []

    def set_target_list(self, target_list: List[str]):
        regex = re.compile(r":([0-9]{2,5})$")
        for target in target_list:
            print(f"target : {target}")
            port = regex.search(target).group(1)
            new_port = f"{int(port) + 1900}"
            endpoint = target.replace(port, new_port)
            self.endpoints.append(endpoint)

        fault: int = int((len(self.endpoints) - 1) / 3)
        self.min_quorum: int = fault * 2 + 1

    async def _fetch_status(self, endpoint: str) -> dict:
        start_time = time.perf_counter()
        client = RestClient(self._channel_name, endpoint)
        response: Dict[str, Any] = await client.call_async(RestMethod.Status)
        logging.info(f"{response}")

        return {
            "target": endpoint,
            "elapsed_time": time.perf_counter() - start_time,
            "height": response.get("block_height"),
            "state": response.get('state'),
        }

    async def wait_recovery(self):
        # TODO : loop target list, check node count which is greater than 2f in recovery mode state

        while True:
            self.recovery_quorum = 0

            results = await asyncio.gather(*[self._fetch_status(endpoint) for endpoint in self.endpoints],
                                           return_exceptions=True)
            logging.debug(f"status results : {results}")
            results = [result for result in results if isinstance(result, dict)]  # to filter exceptions

            for result in results:  # type: dict
                if result.get("state") == "RecoveryMode":
                    self.recovery_quorum += 1

            """
            for target in self.target_list:  # type: str
                client = RestClient(self._channel_name, target)
                response: Dict[str, Any] = await client.call_async(RestMethod.Status)

                if response.get("state") == "RecoverMode":
                    self.recovery_quorum += 1
            """

            logging.info(f"recovery_quorum : {self.recovery_quorum}")
            if self.recovery_quorum >= self.min_quorum:
                await asyncio.sleep(self.waiting_sec + 1)
                return

            await asyncio.sleep(self.waiting_sec)
