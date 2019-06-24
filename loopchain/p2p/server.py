""" P2P Server """

import abc
from typing import Type

from .bridge import PeerBridgeBase
from .grpc_helper import GRPCHelper
from .peer_outer_service import PeerOuterService
from .protos import loopchain_pb2_grpc


class P2PServerBase(abc.ABC):
    """ Peer to Peer Server abstract class

    """

    def __init__(self, peer_port: int = None, peer_bridge: PeerBridgeBase = None):
        self._peer_port = peer_port
        self._peer_bridge = peer_bridge

    @abc.abstractmethod
    def start(self) -> None:
        pass

    @abc.abstractmethod
    def stop(self) -> None:
        pass


class GrpcServer(P2PServerBase):
    """ GRPC server
    """

    def __init__(self, peer_port: int = None, peer_bridge: PeerBridgeBase = None):
        super().__init__(peer_port, peer_bridge)
        self._outer_service = None
        self._outer_server = None

    def start(self) -> None:
        """

        :return:
        """

        # FIXME : peer outer service using interface
        self._outer_service = PeerOuterService(self._peer_bridge)
        self._outer_server = GRPCHelper().start_outer_server(str(self._peer_port))
        loopchain_pb2_grpc.add_PeerServiceServicer_to_server(self._outer_service, self._outer_server)

    def stop(self) -> None:
        """

        :return:
        """
        self._outer_server.stop(None)


class ZeromqServer(P2PServerBase):
    """ ZeroMQ server
    """

    def __init__(self, peer_port: int = None, peer_bridge: PeerBridgeBase = None):
        super().__init__(peer_port, peer_bridge)

    def start(self) -> None:
        """
        TODO : start p2p server with zeromq
        :return:
        """
        pass

    def stop(self) -> None:
        """ stop zeroMQ server
        TODO : stop zeromq server
        :return:
        """
        pass


class P2PServer:
    def __init__(self,
                 peer_port: int = None,
                 peer_bridge: PeerBridgeBase = None,
                 server_class: Type[P2PServerBase] = GrpcServer):
        self._server: P2PServerBase = server_class(peer_port=peer_port, peer_bridge=peer_bridge)

    def start(self):
        self._server.start()

    def stop(self):
        self._server.stop()
