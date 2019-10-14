# Copyright 2018 ICON Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""The Client Interface for REST call."""

import asyncio
import logging
from collections import namedtuple
from typing import List, Optional, NamedTuple
from urllib.parse import urlparse

import requests
from aiohttp import ClientSession
from jsonrpcclient import HTTPClient, Request
from loopchain import utils, configure as conf


RestMethod = namedtuple("RestMethod", "version name params")


class RestMethods:
    GetChannelInfos = RestMethod(conf.ApiVersion.node, "node_getChannelInfos", None)
    GetBlockByHeight = RestMethod(conf.ApiVersion.node, "node_getBlockByHeight", namedtuple("Params", "height"))
    Status = RestMethod(conf.ApiVersion.v1, "/status/peer", None)
    GetLastBlock = RestMethod(conf.ApiVersion.v3, "icx_getLastBlock", None)
    GetReps = RestMethod(conf.ApiVersion.v3, "rep_getListByHash", namedtuple("Params", "repsHash"))


class RestClient:
    def __init__(self, channel=None):
        self._target: str = None
        self._channel_name = channel or conf.LOOPCHAIN_DEFAULT_CHANNEL

    async def init(self, endpoints: List[str]):
        self._target = await self._select_fastest_endpoint(endpoints)
        if self._target:
            utils.logger.spam(f"RestClient init target({self._target})")

    @property
    def target(self):
        return self._target

    async def _fetch_status(self, session: ClientSession, request_uri):
        endpoint_target = f"{urlparse(request_uri).scheme}://{urlparse(request_uri).netloc}"
        start_time = session.loop.time()
        async with session.get(url=request_uri,
                               params={'channel': self._channel_name},
                               timeout=conf.REST_TIMEOUT) as response:
            response_dict = await response.json()
            block_height = response_dict['block_height']
            elapsed_time = session.loop.time() - start_time
            return {
                'target': endpoint_target,
                'elapsed_time': elapsed_time,
                'height': block_height
            }

    async def _select_fastest_endpoint(self, endpoints) -> Optional[str]:
        """select fastest endpoint with conditions below
        1. Maximum block height (higher priority)
        2. Minimum elapsed response time

        :param endpoints: list of endpoints
        :return: the fastest endpoint target "{scheme}://{netloc}"
        """
        path = RestMethods.Status.name
        endpoints = [utils.normalize_request_url(endpoint, conf.ApiVersion.v1) + path for endpoint in endpoints]
        async with ClientSession() as session:
            results = await asyncio.gather(*[self._fetch_status(session, endpoint) for endpoint in endpoints],
                                           return_exceptions=True)
            results = [result for result in results if isinstance(result, dict)]  # to filter exceptions

        if not results:
            logging.warning(f"no alive node among endpoints({endpoints})")
            return None

        # sort results by min elapsed_time with max block height
        sorted_result = sorted(results, key=lambda k: (-k['height'], k['elapsed_time']))
        min_latency_target = sorted_result[0]['target']
        logging.info(f"minimum latency endpoint is: {min_latency_target}")
        return min_latency_target

    def call(self, method: RestMethod, params: Optional[NamedTuple] = None, timeout=None) -> dict:
        timeout = timeout or conf.REST_ADDITIONAL_TIMEOUT

        try:
            if method.version == conf.ApiVersion.v1:
                response = self._call_rest(method, timeout)
            else:
                response = self._call_jsonrpc(method, params, timeout)
            utils.logger.spam(f"REST call complete method_name({method.name})")
            return response
        except Exception as e:
            logging.warning(f"REST call fail method_name({method.name}), caused by : {type(e)}, {e}")
            raise e

    def _call_rest(self, method: RestMethod, timeout):
        url = utils.normalize_request_url(self._target, method.version, self._channel_name)
        url += method.name
        response = requests.get(url=url,
                                params={'channel': self._channel_name},
                                timeout=timeout)
        if response.status_code != 200:
            raise ConnectionError
        return response.json()

    def _call_jsonrpc(self, method: RestMethod, params: Optional[NamedTuple], timeout):
        url = utils.normalize_request_url(self._target, method.version, self._channel_name)
        http_client = HTTPClient(url)

        # 'vars(namedtuple)' does not working in Python 3.7.4
        # noinspection PyProtectedMember
        request = Request(method.name, params._asdict()) if params else Request(method.name)
        try:
            return http_client.send(request, timeout=timeout)
        except Exception as e:
            raise ConnectionError(e)
