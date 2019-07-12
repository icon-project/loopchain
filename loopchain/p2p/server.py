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
""" P2P Server """

import abc
from typing import Type

from .grpc_helper import GRPCHelper
from loopchain.p2p.peer_outer_service import PeerOuterService
from .protos import loopchain_pb2_grpc


class P2PServerBase(abc.ABC):
    """ Peer to Peer Server abstract class

    """
    def __init__(self, peer_port: int = None):
        self._peer_port = peer_port

    @abc.abstractmethod
    def start(self) -> None:
        pass

    @abc.abstractmethod
    def stop(self) -> None:
        pass


class GrpcServer(P2PServerBase):
    """ GRPC server
    """

    def __init__(self, peer_port: int = None):
        super().__init__(peer_port)
        self._outer_service = None
        self._outer_server = None

    def start(self) -> None:
        """

        :return:
        """

        # FIXME : peer outer service using interface
        self._outer_service = PeerOuterService()
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

    def __init__(self, peer_port: int = None):
        super().__init__(peer_port)

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
    def __init__(self, peer_port: int = None,
                 server_class: Type[P2PServerBase] = GrpcServer):
        self._server: P2PServerBase = server_class(peer_port=peer_port)

    def start(self):
        self._server.start()

    def stop(self):
        self._server.stop()
