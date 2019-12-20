"""A management class for radiostation node pool"""

import concurrent
import logging
import time
from itertools import cycle
from typing import Optional, Sequence, Iterator, Dict
from urllib.parse import urlparse

from loopchain import utils, configure as conf
from loopchain.baseservice.rest_client import RestMethod, RestClient


class NodePool:
    def __init__(self, channel):
        self.channel = channel
        self._rest_client = RestClient(channel)
        self._target: Optional[str] = None
        self._nearest_targets: Optional[Iterator] = None

    @property
    def target(self):
        return self._target

    def find(self):
        endpoints = self._get_all_endpoints()

        self._nearest_targets = self._find_nearest_endpoints(endpoints)
        print("nearst: ", self._nearest_targets)

        if self._nearest_targets:
            min_latency_target = next(self._nearest_targets)['target']  # get first target
            self._set_target(min_latency_target)

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

        if self._target and len(endpoints) > 1:
            endpoints.remove(self._target)

        return endpoints

    def _find_nearest_endpoints(self, endpoints: Sequence[str]) -> Optional[Iterator[Dict]]:
        """select fastest endpoint with conditions below
        1. Maximum block height (highest priority)
        2. Minimum elapsed response time
        3. target's state in ("Vote", "LeaderComplain", "Watch")

        :param endpoints: list of endpoints information
        :return: the fastest endpoint target "{scheme}://{netloc}"
        """

        with concurrent.futures.ThreadPoolExecutor() as pool:
            results = pool.map(self._fetch_status, endpoints)

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

    def _fetch_status(self, endpoint: str) -> Optional[Dict]:
        start_time = time.time()
        response = self._rest_client.call(endpoint, RestMethod.Status, conf.REST_TIMEOUT)
        if response.get('state') not in ("Vote", "LeaderComplain", "Watch"):
            return None

        return {
            'target': endpoint,
            'elapsed_time': time.time() - start_time,
            'height': response['block_height']
        }
