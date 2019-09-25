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
"""PeerInfo for shared peer info and PeerLiveData for instance data can't serialized"""

import json
import logging
import typing

from loopchain import configure as conf
from loopchain.baseservice import StubManager
from loopchain.protos import loopchain_pb2_grpc


class Peer:
    """Peer Object"""

    STATUS_UPDATE_TIME_FORMAT = '%Y-%m-%d %H:%M:%S.%f'

    def __init__(self,
                 peer_id: str,
                 target: str = "",
                 order: int = 0):
        """

        :param peer_id: peer_id
        :param target: gRPC target info default ""
        :param order:
        :return:
        """
        self.peer_id: str = peer_id
        self.order: int = order
        self.target: str = target

        # live data, It is not revealed from deserialize.
        self.__stub_manager: typing.Optional[StubManager] = None
        self.__cert_verifier = None

    @property
    def stub_manager(self):
        if not self.__stub_manager:
            try:
                self.__stub_manager = StubManager(self.target,
                                                  loopchain_pb2_grpc.PeerServiceStub,
                                                  conf.GRPC_SSL_TYPE)
            except Exception as e:
                logging.exception(f"Create Peer create stub_manager fail target : {self.target} \n"
                                  f"exception : {e}")

        return self.__stub_manager

    def serialize(self) -> dict:
        return {
            'peer_id': self.peer_id,
            'order': self.order,
            'target': self.target
        }

    @staticmethod
    def deserialize(peer_serialized: dict) -> 'Peer':
        peer = Peer(peer_id=peer_serialized['peer_id'],
                    target=peer_serialized['target'],
                    order=peer_serialized['order'])
        return peer

    def dump(self) -> bytes:
        serialized = self.serialize()
        return json.dumps(serialized).encode(encoding=conf.PEER_DATA_ENCODING)

    @staticmethod
    def load(peer_dumped: bytes):
        serialized = json.loads(peer_dumped.decode(encoding=conf.PEER_DATA_ENCODING))
        return Peer.deserialize(serialized)
