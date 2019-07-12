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

""" p2p service """
import logging
from enum import IntEnum
from typing import Dict

from loopchain import configure as conf
from loopchain.p2p.grpc_helper import GRPCHelper
from loopchain.p2p.protos import loopchain_pb2_grpc, loopchain_pb2
from loopchain.p2p.server import P2PServer
from loopchain.p2p.stub_manager import StubManager

try:
    from loopchain.p2p.server import GrpcServer as P2PServerClass
except ImportError as exc:
    logging.warning(f"can't import GrpcServer cause by {exc}. try import ZeromqServer")
    from loopchain.p2p.server import ZeromqServer as P2PServerClass


class PeerType(IntEnum):
    PEER = loopchain_pb2.PEER                           # 0
    BLOCK_GENERATOR = loopchain_pb2.BLOCK_GENERATOR     # 1
    RADIO_STATION = loopchain_pb2.RADIO_STATION         # 2


class NodeType(IntEnum):
    CITIZEN_NODE = loopchain_pb2.CitizenNode            # 1
    COMMUNITY_NODE = loopchain_pb2.CommunityNode        # 3


class P2PService:
    """P2P network service is to control P2PServer and P2PClient
    """

    def __init__(self, peer_port: int = None):
        """
        :param peer_port: peer port number
        """
        self._peer_port: int = peer_port

        # client for p2p networking (like stub_manager?)
        # TODO : change StubManager to P2PClient
        # self._clients: Dict[str, P2PClient] = {}
        self._clients: Dict[str, StubManager] = {}

        # server for p2p networking (like peer outer service?)
        self._server: P2PServer = None

    def get_client(self, target: str) -> StubManager:
        """ get p2p client for target (ip:port)
        TODO : return P2PClient
        :param target:
        :return:
        """
        client = self._clients.get(target, None)

        if not client:
            logging.warning(f"not found client for {target}")

        return client

    def add_client(self, target: str) -> None:
        """ add p2p client for peer target (ip:port)
        TODO : change stub_manager to P2PClient
        :param target:
        :return:
        """
        stub_manager = StubManager(target,
                                   loopchain_pb2_grpc.PeerServiceStub,
                                   conf.GRPC_SSL_TYPE)

        self._clients[target] = stub_manager

    def remove_client(self, target: str):
        """ remove p2p client matching target (ip:port)

        :param target:
        :return:
        """
        try:
            del self._clients[target]
        except KeyError as e:
            logging.error(e)

    def start_server(self) -> None:
        """ start p2p server

        :return: P2PService instance
        """
        if not self._server:
            # TODO : distinguish server_class for grpc or zeromq
            self._server = P2PServer(peer_port=self._peer_port, server_class=P2PServerClass)

        self._server.start()

    def stop_server(self) -> None:
        """ stop p2p server

        :return:
        """
        self._server.stop()

    def call_and_retry(self, stub_to_radiostation, peer_id, peer_target):
        """ call and retry while timeout
        TODO : refactoring method name

        :param stub_to_radiostation:
        :param peer_id:
        :param peer_target:
        :return:
        """
        response = stub_to_radiostation.call_in_times(
            method_name="GetChannelInfos",
            message=loopchain_pb2.GetChannelInfosRequest(
                peer_id=peer_id,
                peer_target=peer_target,
                group_id=peer_id),
            retry_times=conf.CONNECTION_RETRY_TIMES_TO_RS,
            is_stub_reuse=False,
            timeout=conf.CONNECTION_TIMEOUT_TO_RS
        )
        return response

    @staticmethod
    def get_peer_service_stub(target) -> loopchain_pb2_grpc.PeerServiceStub:
        channel = GRPCHelper().create_client_channel(target)
        return loopchain_pb2_grpc.PeerServiceStub(channel)
