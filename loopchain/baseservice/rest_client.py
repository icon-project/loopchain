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
from typing import List, Optional
from urllib.parse import urlparse

import requests
from aiohttp import ClientSession
from jsonrpcclient import HTTPClient, Request

from loopchain import configure as conf
from loopchain import utils


class RestClient:
    def __init__(self, channel=None):
        self._target: str = None
        self._channel_name = channel or conf.LOOPCHAIN_DEFAULT_CHANNEL
        self._version_urls = {}
        self._http_clients = {}
        self._method_versions = {
            "GetChannelInfos": conf.ApiVersion.node,
            "GetBlockByHeight": conf.ApiVersion.node,
            "Status": conf.ApiVersion.v1,
            "GetLastBlock": conf.ApiVersion.v3,
            "GetReps": conf.ApiVersion.v3
        }
        self._method_names = {
            "GetChannelInfos": "node_getChannelInfos",
            "GetBlockByHeight": "node_getBlockByHeight",
            "Status": "/status/peer",
            "GetLastBlock": "icx_getLastBlock",
            "GetReps": "rep_getListByHash"
        }

    async def init(self, endpoints: List[str]):
        self._target = await self._select_fastest_endpoint(endpoints)
        if self._target:
            utils.logger.spam(f"RestClient init target({self._target})")
            self._init_http_clients()

    @property
    def target(self):
        return self._target

    def _init_http_clients(self):
        for version in conf.ApiVersion:
            url = utils.normalize_request_url(self._target, version, self._channel_name)
            self._version_urls[version] = url
            if version != conf.ApiVersion.v1:
                self._http_clients[url] = HTTPClient(url)

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
        path = self._method_names["Status"]
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

    def call(self, method_name, params=None, timeout=None) -> dict:
        try:
            version = self._method_versions[method_name]
            url = self._version_urls[version]
            method_name = self._method_names[method_name]
            timeout = timeout or conf.REST_ADDITIONAL_TIMEOUT

            if version == conf.ApiVersion.v1:
                url += method_name
                response = requests.get(url=url,
                                        params={'channel': self._channel_name},
                                        timeout=timeout)
                if response.status_code != 200:
                    raise ConnectionError
                response = response.json()
            else:
                # using jsonRPC client request.
                request = Request(method_name, params) if params else Request(method_name)

                try:
                    response = self._http_clients[url].send(request, timeout=timeout)
                except Exception as e:
                    raise ConnectionError(e)
            utils.logger.spam(f"REST call complete request_url({url}), method_name({method_name})")
            return response

        except Exception as e:
            logging.warning(f"REST call fail method_name({method_name}), caused by : {type(e)}, {e}")
            raise e
