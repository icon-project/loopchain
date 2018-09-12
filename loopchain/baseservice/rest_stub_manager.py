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
from jsonrpcclient.exceptions import ReceivedErrorResponse
from jsonrpcclient.http_client import HTTPClient

import loopchain.utils as util
from loopchain import configure as conf


class RestStubManager:
    def __init__(self, target, for_rs_target=True):
        util.logger.spam(f"RestStubManager:init target({target})")

        self.__target = target

        self.__version_urls = {}
        for version in conf.ApiVersion:
            if 'https://' in target:
                url = util.normalize_request_url(target, version.name)
            elif for_rs_target:
                url = util.normalize_request_url(
                    f"{'https' if conf.SUBSCRIBE_USE_HTTPS else 'http'}://{target}", version.name)
            else:
                url = util.normalize_request_url(f"http://{target}", version.name)
            self.__version_urls[version] = url

        self.__method_versions = {
            "Subscribe": conf.ApiVersion.node,
            "Unsubscribe": conf.ApiVersion.node,
            "GetChannelInfos": conf.ApiVersion.node,
            "AnnounceConfirmedBlock": conf.ApiVersion.node,
            "GetBlockByHeight": conf.ApiVersion.node,
            "Status": conf.ApiVersion.v1,
            "GetLastBlock": conf.ApiVersion.v2
        }

        self.__method_names = {
            "Subscribe": "node_Subscribe",
            "Unsubscribe": "node_Unsubscribe",
            "GetChannelInfos": "node_GetChannelInfos",
            "AnnounceConfirmedBlock": "node_AnnounceConfirmedBlock",
            "GetBlockByHeight": "node_GetBlockByHeight",
            "Status": "/status/peer/",
            "GetLastBlock": "icx_getLastBlock"
        }

        self.__executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="RestStubThread")
        self.update_methods_version()

    @property
    def target(self):
        return self.__target

    def update_methods_version(self):
        method_name = "GetBlockByHeight"

        try:
            HTTPClient(self.__version_urls[conf.ApiVersion.node]).request(
                method_name="node_GetBlockByHeight",
                message={'height': 0}
            )
            self.__method_versions[method_name] = conf.ApiVersion.node
            self.__method_names[method_name] = "node_GetBlockByHeight"
        except ReceivedErrorResponse as e:
            self.__method_versions[method_name] = conf.ApiVersion.v2
            self.__method_names[method_name] = "icx_getBlockByHeight"

        logging.debug(f"update subscribe api version({method_name}) to: {self.__method_versions[method_name].name}")

    def call(self, method_name, message=None, timeout=None, is_stub_reuse=True, is_raise=False):
        try:
            version = self.__method_versions[method_name]
            url = self.__version_urls[version]
            method_name = self.__method_names[method_name]

            if version == conf.ApiVersion.v1:
                url += method_name
                response = requests.get(url)
            else:
                client = HTTPClient(url)
                client.session.verify = conf.REST_SSL_VERIFY
                if version == conf.ApiVersion.v2:
                    response = client.request(method_name, message)
                else:
                    response = client.request(method_name=method_name, message=message)

            util.logger.spam(f"RestStubManager:call complete request_url({url}), "
                             f"method_name({method_name})")
            return response

        except Exception as e:
            logging.warning(f"REST call fail method_name({method_name}), caused by : {e}")
            raise e

    def call_async(self, method_name, message, call_back=None, timeout=None, is_stub_reuse=True):
        future = self.__executor.submit(self.call, method_name, message, timeout, is_stub_reuse)
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
