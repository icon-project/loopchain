# Copyright 2019 ICON Foundation
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
import time
from collections import namedtuple
from enum import Enum
from typing import List, Optional, NamedTuple, Sequence, Iterator, Dict
from urllib.parse import urlparse

import requests
from aiohttp import ClientSession
from jsonrpcclient.clients.aiohttp_client import AiohttpClient
from jsonrpcclient.clients.http_client import HTTPClient
from jsonrpcclient.requests import Request
from jsonrpcclient.response import Response
from loopchain import utils, configure as conf

_RestMethod = namedtuple("_RestMethod", "version name params")


class RestMethod(Enum):
    GetChannelInfos = _RestMethod(conf.ApiVersion.node, "node_getChannelInfos", None)
    GetBlockByHeight = _RestMethod(conf.ApiVersion.node, "node_getBlockByHeight", namedtuple("Params", "height"))
    Status = _RestMethod(conf.ApiVersion.v1, "/status/peer", None)
    GetLastBlock = _RestMethod(conf.ApiVersion.v3, "icx_getLastBlock", None)
    GetReps = _RestMethod(conf.ApiVersion.v3, "rep_getListByHash", namedtuple("Params", "repsHash"))
    SendTransaction2 = _RestMethod(conf.ApiVersion.v2, "icx_sendTransaction",
                                   namedtuple("Params", "from_ to value fee timestamp nonce tx_hash signature"))
    SendTransaction3 = _RestMethod(conf.ApiVersion.v3, "icx_sendTransaction",
                                   namedtuple("Params",
                                              ("from_", "to", "version", "stepLimit", "timestamp", "nid", "signature",
                                               "dataType", "data", "value", "nonce"),
                                              defaults=(None, None, None, None)))


class RestClient:
    def __init__(self, channel=None):
        self._target: str = None
        self._latest_targets: Iterator[Dict] = None
        self._channel_name = channel or conf.LOOPCHAIN_DEFAULT_CHANNEL

    async def init(self, endpoints: List[str]):
        self._latest_targets = await self._select_fastest_endpoints(endpoints)
        if self._latest_targets:
            min_latency_target = next(self._latest_targets)['target']  # get first target
            self._set_target(min_latency_target)

    def init_next_target(self):
        logging.debug(f"switching target from: {self._target}")
        if not self._latest_targets:
            return
        next_target = next(self._latest_targets)['target']
        logging.debug(f"switching target to: {next_target}")
        self._set_target(next_target)

    def _set_target(self, target):
        self._target = self._normalize_target(target)
        logging.info(f"RestClient init target({self._target})")

    @staticmethod
    def _normalize_target(min_latency_target):
        normalized_target = utils.normalize_request_url(min_latency_target)
        return f"{urlparse(normalized_target).scheme}://{urlparse(normalized_target).netloc}"

    @property
    def target(self):
        return self._target

    async def _fetch_status(self, endpoint: str):
        start_time = time.time()
        response = await self._call_async_rest(endpoint, RestMethod.Status, conf.REST_TIMEOUT)

        return {
            'target': endpoint,
            'elapsed_time': time.time() - start_time,
            'height': response['block_height']
        }

    async def _select_fastest_endpoints(self, endpoints: Sequence[str]) -> Optional[Iterator[Dict]]:
        """select fastest endpoint with conditions below
        1. Maximum block height (higher priority)
        2. Minimum elapsed response time

        :param endpoints: list of endpoints
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
        return iter(sorted_result)

    def call(self, method: RestMethod, params: Optional[NamedTuple] = None, timeout=None) -> dict:
        timeout = timeout or conf.REST_ADDITIONAL_TIMEOUT

        try:
            if method.value.version == conf.ApiVersion.v1:
                response = self._call_rest(self.target, method, timeout)
            else:
                response = self._call_jsonrpc(self.target, method, params, timeout)
        except Exception as e:
            logging.warning(f"REST call fail method_name({method.value.name}), caused by : {type(e)}, {e}")
            raise
        else:
            utils.logger.spam(f"REST call complete method_name({method.value.name})")
            return response

    async def call_async(self, method: RestMethod, params: Optional[NamedTuple] = None, timeout=None) -> dict:
        timeout = timeout or conf.REST_ADDITIONAL_TIMEOUT

        try:
            if method.value.version == conf.ApiVersion.v1:
                response = await self._call_async_rest(self.target, method, timeout)
            else:
                response = await self._call_async_jsonrpc(self.target, method, params, timeout)
        except Exception as e:
            logging.warning(f"REST call async fail method_name({method.value.name}), caused by : {type(e)}, {e}")
            raise
        else:
            utils.logger.spam(f"REST call async complete method_name({method.value.name})")
            return response

    def _call_rest(self, target: str, method: RestMethod, timeout):
        url = self._create_rest_url(target, method)
        params = self._create_rest_params()
        response = requests.get(url=url,
                                params=params,
                                timeout=timeout)
        if response.status_code != 200:
            raise ConnectionError
        return response.json()

    def _call_jsonrpc(self, target: str, method: RestMethod, params: Optional[NamedTuple], timeout):
        url = self._create_jsonrpc_url(target, method)
        http_client = HTTPClient(url)
        request = self._create_jsonrpc_params(method, params)

        response: Response = http_client.send(request, timeout=timeout)
        if isinstance(response.data, list):
            raise NotImplementedError(f"Received batch response. Data: {response.data}")
        else:
            return response.data.result

    async def _call_async_rest(self, target: str, method: RestMethod, timeout):
        url = self._create_rest_url(target, method)
        params = self._create_rest_params()
        async with ClientSession() as session:
            async with session.get(url=url,
                                   params=params,
                                   timeout=timeout) as response:
                return await response.json()

    async def _call_async_jsonrpc(self, target: str, method: RestMethod, params: Optional[NamedTuple], timeout: int):
        url = self._create_jsonrpc_url(target, method)
        async with ClientSession() as session:
            http_client = AiohttpClient(session, url, timeout=timeout)
            request = self._create_jsonrpc_params(method, params)

            response: Response = await http_client.send(request)

        if isinstance(response.data, list):
            raise NotImplementedError(f"Received batch response. Data: {response.data}")
        else:
            return response.data.result

    def create_url(self, target: str, method: RestMethod):
        if method.value.version == conf.ApiVersion.v1:
            return self._create_rest_url(target, method)
        else:
            return self._create_jsonrpc_url(target, method)

    def _create_rest_url(self, target: str, method: RestMethod):
        url = utils.normalize_request_url(target, method.value.version, self._channel_name)
        url += method.value.name
        return url

    def _create_jsonrpc_url(self, target: str, method: RestMethod):
        return utils.normalize_request_url(target, method.value.version, self._channel_name)

    def create_params(self, method: RestMethod, params: Optional[NamedTuple]):
        if method.value.version == conf.ApiVersion.v1:
            return self._create_rest_params()
        else:
            return self._create_jsonrpc_params(method, params)

    def _create_rest_params(self):
        return {
            "channel": self._channel_name
        }

    def _create_jsonrpc_params(self, method: RestMethod, params: Optional[NamedTuple]):
        # 'vars(namedtuple)' does not working in Python 3.7.4
        # noinspection PyProtectedMember
        params = params._asdict() if params else None
        if params:
            params = { k: v for k, v in params.items() if v is not None}
            if "from_" in params:
                params["from"] = params.pop("from_")

        return Request(method.value.name, **params) if params else Request(method.value.name)

