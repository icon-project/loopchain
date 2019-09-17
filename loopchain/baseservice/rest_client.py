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

import logging
from typing import List, Dict, Optional
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
            "Status": "/status/peer/",
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
            # TODO required post review [LC-454]
            # if 'https://' in self._target:
            #     url = utils.normalize_request_url(self._target, version, self._channel_name)
            # else:
            #     scheme = 'https' if conf.SUBSCRIBE_USE_HTTPS else 'http'
            #     url = utils.normalize_request_url(f"{scheme}://{self._target}", version, self._channel_name)
            url = utils.normalize_request_url(self._target, version, self._channel_name)
            self._version_urls[version] = url
            if version != conf.ApiVersion.v1:
                self._http_clients[url] = HTTPClient(url)

    async def _select_fastest_endpoint(self, endpoints) -> Optional[str]:
        latencies: Dict[str, float] = dict()
        for endpoint in endpoints:
            request_uri = utils.normalize_request_url(endpoint, conf.ApiVersion.v1)
            neighbor_target = urlparse(request_uri).scheme + "://" + urlparse(request_uri).netloc
            try:
                async with ClientSession() as session:
                    start_time = session.loop.time()
                    await session.get(request_uri,
                                      params={'channel': self._channel_name},
                                      timeout=conf.REST_ADDITIONAL_TIMEOUT)
                    elapsed_time = session.loop.time() - start_time
            except Exception:
                continue
            else:
                latencies[neighbor_target] = elapsed_time

        if not latencies:
            logging.warning(f"no alive node among endpoints({endpoints})")
            return

        min_latency_target = min(latencies.keys(), key=lambda k: latencies[k])
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
