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
"""A stub wrapper for REST call.
This object has same interface with gRPC stub manager"""
import logging
from concurrent.futures import ThreadPoolExecutor

import requests
from jsonrpcclient import HTTPClient, Request

import loopchain.utils as util
from loopchain import configure as conf


class RestStubManager:
    def __init__(self, target, channel=None, for_rs_target=True):
        util.logger.spam(f"RestStubManager:init target({target})")
        self._channel_name = channel or conf.LOOPCHAIN_DEFAULT_CHANNEL
        self._version_urls = {}
        self._http_clients = {}
        for version in conf.ApiVersion:
            if 'https://' in target:
                url = util.normalize_request_url(target, version, self._channel_name)
            elif for_rs_target:
                url = util.normalize_request_url(
                    f"{'https' if conf.SUBSCRIBE_USE_HTTPS else 'http'}://{target}", version, self._channel_name)
            else:
                url = util.normalize_request_url(f"http://{target}", version, self._channel_name)
            self._version_urls[version] = url
            if version != conf.ApiVersion.v1:
                self._http_clients[url] = HTTPClient(url)

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
            "GetReps": "rep_getList"
        }

        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="RestStubThread")

    def call(self, method_name, message=None, timeout=None, is_stub_reuse=True, is_raise=False) -> dict:
        try:
            version = self._method_versions[method_name]
            url = self._version_urls[version]
            method_name = self._method_names[method_name]

            if version == conf.ApiVersion.v1:
                url += method_name
                response = requests.get(url=url,
                                        params={'channel': self._channel_name},
                                        timeout=conf.REST_ADDITIONAL_TIMEOUT)
                if response.status_code != 200:
                    raise ConnectionError
                response = response.json()
            else:
                # using jsonRPC client request.
                if message:
                    request = Request(method_name, message)
                else:
                    request = Request(method_name)

                try:
                    response = self._http_clients[url].send(request, timeout=conf.REST_ADDITIONAL_TIMEOUT)
                except Exception as e:
                    raise ConnectionError(e)
            util.logger.spam(f"REST call complete request_url({url}), method_name({method_name})")
            return response

        except Exception as e:
            logging.warning(f"REST call fail method_name({method_name}), caused by : {type(e)}, {e}")
            raise e

    def call_async(self, method_name, message=None, call_back=None, timeout=None, is_stub_reuse=True):
        future = self._executor.submit(self.call, method_name, message, timeout, is_stub_reuse)
        if call_back:
            future.add_done_callback(call_back)
        return future

    def call_in_times(self, method_name, message=None, retry_times=None, is_stub_reuse=True, timeout=conf.GRPC_TIMEOUT):
        retry_times = conf.BROADCAST_RETRY_TIMES if retry_times is None else retry_times

        exception = None
        for i in range(retry_times):
            try:
                return self.call(method_name, message)
            except Exception as e:
                exception = e

        raise exception
