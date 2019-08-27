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
"""Wrapper for Stub to Peer Service"""

import json
from json import JSONDecodeError

from loopchain import configure as conf
from loopchain.baseservice import StubManager
from loopchain.components import SingletonMetaClass
from loopchain.protos import loopchain_pb2, loopchain_pb2_grpc


class PeerServiceStub(metaclass=SingletonMetaClass):
    REST_GRPC_TIMEOUT = conf.GRPC_TIMEOUT + conf.REST_ADDITIONAL_TIMEOUT

    def __init__(self):
        self.__stub_to_peer_service = None

    def set_stub_port(self, port):
        ip_address = conf.IP_LOCAL
        self.__stub_to_peer_service = StubManager(
            ip_address + ':' + str(port), loopchain_pb2_grpc.PeerServiceStub, conf.GRPC_SSL_TYPE)

    @property
    def stub(self):
        return self.__stub_to_peer_service

    def call(self, *args):
        # util.logger.spam(f"peer_service_stub:call target({self.__stub_to_peer_service.target})")
        return self.__stub_to_peer_service.call(*args)

    def get_status(self, channel: str):
        response = self.call("GetStatus",
                             loopchain_pb2.StatusRequest(request="", channel=channel),
                             self.REST_GRPC_TIMEOUT)
        status_json_data = json.loads(response.status)
        status_json_data['block_height'] = response.block_height
        status_json_data['unconfirmed_block_height'] = response.unconfirmed_block_height
        status_json_data['total_tx'] = response.total_tx
        status_json_data['leader_complaint'] = response.is_leader_complaining

        return status_json_data

    def get_transaction(self, tx_hash: str, channel: str):
        return self.call("GetTx",
                         loopchain_pb2.GetTxRequest(tx_hash=tx_hash, channel=channel),
                         self.REST_GRPC_TIMEOUT)

    def get_invoke_result(self, tx_hash, channel):
        return self.call("GetInvokeResult",
                         loopchain_pb2.GetInvokeResultRequest(tx_hash=tx_hash, channel=channel),
                         self.REST_GRPC_TIMEOUT)

    def request(self, channel, code, params):
        response = self.call(
            "Request", loopchain_pb2.Message(
                code=code,
                channel=channel,
                meta=params
            ), self.REST_GRPC_TIMEOUT)

        try:
            response_data = json.loads(response.meta)
        except JSONDecodeError as e:
            response_data = json.loads("{}")
            response_data['response'] = response.meta
        response_data['response_code'] = response.code
        return response_data
