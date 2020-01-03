"""A management class for radiostation node pool"""

import asyncio
import logging
from typing import Optional, Sequence, Iterator, Dict
from urllib.parse import urlparse

import time
from itertools import cycle

from loopchain import utils, configure as conf
from loopchain.baseservice.rest_client import RestMethod, RestClient


class NodePool:
    def __init__(self, channel):
        self.channel = channel
        self._rest_client = RestClient(channel)
        self._target: Optional[str] = None
        self._nearest_targets: Optional[Iterator] = None

        loop = asyncio.get_event_loop()
        loop.create_task(self._find())

    @property
    def target(self):
        return self._target

    async def _find(self):
        while True:
            endpoints = self._get_all_endpoints()
            self._nearest_targets = await self._find_nearest_endpoints(endpoints)
            if self._nearest_targets:
                min_latency_target = next(self._nearest_targets)['target']  # get first target
                self._set_target(min_latency_target)
            await asyncio.sleep(conf.CONNECTION_RETRY_TIMEOUT)

    def find_next(self):
        next_target = next(self._nearest_targets)['target']
        logging.debug(f"switching target from({self._target}) to({next_target})")
        self._set_target(next_target)

    def _set_target(self, target):
        self._target = self._normalize_target(target)
        logging.info(f"NodePool setting target({self._target})")

    def _get_all_endpoints(self):
        endpoints: list = conf.CHANNEL_OPTION[self.channel].get('radiostations')
        if not endpoints:
            raise RuntimeError(f"no configurations for radiostations.")

        endpoints = utils.convert_local_ip_to_private_ip(endpoints)
        return endpoints

    async def _find_nearest_endpoints(self, endpoints: Sequence[str]) -> Optional[Iterator[Dict]]:
        """select fastest endpoint with conditions below
        1. Maximum block height (highest priority)
        2. Minimum elapsed response time
        3. target's state in ("Vote", "LeaderComplain", "Watch")

        :param endpoints: list of endpoints information
        :return: the fastest endpoint target "{scheme}://{netloc}"
        """
        results = await asyncio.gather(*[self._fetch_status(endpoint) for endpoint in endpoints],
                                       return_exceptions=True)
        results = [result for result in results if isinstance(result, dict)]  # to filter exceptions

        if not results:
            logging.warning(f"no alive node among endpoints({endpoints})")
            return None

        # sort results by min elapsed_time with max block height
        sorted_result = sorted(results, key=lambda k: (-k['height'], k['elapsed_time']))
        utils.logger.spam(f"nearest_endpoints: {sorted_result}, len({sorted_result})")
        return cycle(sorted_result)

    @staticmethod
    def _normalize_target(min_latency_target):
        normalized_target = utils.normalize_request_url(min_latency_target)
        return f"{urlparse(normalized_target).scheme}://{urlparse(normalized_target).netloc}"

    async def _fetch_status(self, endpoint: str) -> Optional[Dict]:
        start_time = time.time()
        response = await self._rest_client.call_async(endpoint, RestMethod.Status, conf.REST_TIMEOUT)
        if response.get('state') not in ("Vote", "LeaderComplain", "Watch"):
            return None

        return {
            'target': endpoint,
            'elapsed_time': time.time() - start_time,
            'height': response['block_height']
        }
