"""Recovery mode"""

import asyncio
import logging
import re
from typing import List, Dict, Any

from loopchain import configure as conf
from loopchain.baseservice.rest_client import RestClient, RestMethod


class Recovery:
    def __init__(self, channel: str):
        self.waiting_sec: int = conf.RECOVERY_WAITING_INTERVAL
        self._channel_name: str = channel
        self.min_quorum: int = 0
        self.endpoints: List[str] = []

    def set_target_list(self, target_list: List[str]):
        regex = re.compile(r":([0-9]{2,5})$")
        for target in target_list:
            print(f"target : {target}")
            port = regex.search(target).group(1)
            new_port = f"{int(port) + conf.PORT_DIFF_REST_SERVICE_CONTAINER}"
            endpoint = target.replace(port, new_port)
            self.endpoints.append(endpoint)

        fault: int = int((len(self.endpoints) - 1) / 3)
        self.min_quorum: int = fault * 2 + 1

    async def _fetch_recovery_mode(self, endpoint: str) -> bool:
        client = RestClient(self._channel_name, endpoint)
        response: Dict[str, Any] = await client.call_async(RestMethod.Status)
        logging.info(f"{response}")

        return response.get("recovery_mode", False)

    async def wait_recovery(self):
        # TODO : loop target list, check node count which is greater than 2f in recovery mode state

        while True:
            results = await asyncio.gather(*[self._fetch_recovery_mode(endpoint) for endpoint in self.endpoints],
                                           return_exceptions=True)
            logging.debug(f"status results : {results}")

            # to filter exceptions
            results = [result for result in results if isinstance(result, bool)]
            recovery_quorum = results.count(True)

            logging.info(f"recovery_quorum : {recovery_quorum}")
            if recovery_quorum >= self.min_quorum:
                await asyncio.sleep(self.waiting_sec + 1)
                return

            await asyncio.sleep(self.waiting_sec)
