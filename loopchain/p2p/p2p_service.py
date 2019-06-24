""" p2p service """

import logging
from enum import IntEnum
from typing import Dict

from loopchain import configure as conf
from loopchain.p2p.bridge import PeerBridgeBase
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

    def __init__(self, peer_port: int = None, peer_bridge: PeerBridgeBase = None):
        """
        :param peer_port: peer port number
        """
        self._peer_port: int = peer_port
        self._peer_bridge = peer_bridge

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
            self._server = P2PServer(peer_port=self._peer_port,
                                     peer_bridge=self._peer_bridge,
                                     server_class=P2PServerClass)

        self._server.start()

    def stop_server(self) -> None:
        """ stop p2p server

        :return:
        """
        self._server.stop()

    @staticmethod
    def get_peer_service_stub(target) -> loopchain_pb2_grpc.PeerServiceStub:
        channel = GRPCHelper().create_client_channel(target)
        return loopchain_pb2_grpc.PeerServiceStub(channel)
