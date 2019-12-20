"""A management class for radiostation node pool"""

import concurrent
import logging
from typing import Optional, Sequence, Dict
from urllib.parse import urlparse

import time

from loopchain import utils, configure as conf
from loopchain.baseservice.rest_client import RestMethod, RestClient


class NodePool:
    def __init__(self, channel):
        self.channel = channel
        self._rest_client = RestClient(channel)
        self._target: Optional[str] = None
        self.find()

    @property
    def target(self):
        return self._target

    def find(self):
        endpoints = self._get_all_endpoints()
        nearest = self._find_nearest(endpoints)

        if nearest:
            self._set_target(nearest['target'])

    def _set_target(self, target):
        self._target = self._normalize_target(target)
        logging.info(f"NodePool setting target({self._target})")

    def _get_all_endpoints(self):
        endpoints: list = conf.CHANNEL_OPTION[self.channel].get('radiostations')
        if not endpoints:
            raise RuntimeError(f"no configurations for radiostations.")

        endpoints = utils.convert_local_ip_to_private_ip(endpoints)

        if self._target and len(endpoints) > 1:
            try:
                old_target = urlparse(self._target).netloc
                endpoints.remove(old_target)
            except ValueError:
                pass

        return endpoints

    def _find_nearest(self, endpoints: Sequence[str]) -> Optional[Dict]:
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
        utils.logger.spam(f"near_endpoints: {sorted_result}, len({len(sorted_result)})")
        return sorted_result[0]

    @staticmethod
    def _normalize_target(min_latency_target):
        normalized_target = utils.normalize_request_url(min_latency_target)
        return f"{urlparse(normalized_target).scheme}://{urlparse(normalized_target).netloc}"

    def _fetch_status(self, endpoint: str) -> Optional[Dict]:
        start_time = time.time()
        try:
            response = self._rest_client.call(endpoint, RestMethod.Status, conf.REST_TIMEOUT)
            if response.get('state') not in ("Vote", "LeaderComplain", "Watch"):
                return None
        except Exception:
            return None

        return {
            'target': endpoint,
            'elapsed_time': time.time() - start_time,
            'height': response['block_height']
        }
