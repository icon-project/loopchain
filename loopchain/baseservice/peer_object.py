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

import datetime
import json
import logging
import typing
from enum import IntEnum

from loopchain import configure as conf
from loopchain.baseservice import StubManager
from loopchain.protos import loopchain_pb2_grpc


class PeerStatus(IntEnum):
    unknown = 0
    connected = 1
    disconnected = 2


class Peer:
    """Peer Object"""

    STATUS_UPDATE_TIME_FORMAT = '%Y-%m-%d %H:%M:%S.%f'

    def __init__(self, peer_id: str, group_id: str,
                 target: str = "", status: PeerStatus = PeerStatus.unknown, order: int = 0):
        """ create PeerInfo
        if connected peer status PeerStatus.connected

        :param peer_id: peer_id
        :param group_id: peer's group_id
        :param target: gRPC target info default ""
        :param status: connect status if db loaded peer to PeerStatus.unknown default ""
        :param order:
        :return:
        """
        self.__peer_id = peer_id
        self.__group_id = group_id
        self.__order: int = order
        self.__target: str = target

        self.__status_update_time = datetime.datetime.now()
        self.__status = status

        # live data, It is not revealed from deserialize.
        self.__stub_manager: typing.Optional[StubManager] = None
        self.__cert_verifier = None

    @property
    def peer_id(self) -> str:
        return self.__peer_id

    @property
    def group_id(self) -> str:
        return self.__group_id

    @property
    def order(self):
        return self.__order

    @order.setter
    def order(self, order: int):
        self.__order = order

    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, target):
        self.__target = target

    @property
    def status(self):
        return self.__status

    @status.setter
    def status(self, status):
        if self.__status != status:
            self.__status_update_time = datetime.datetime.now()
            self.__status = status

    @property
    def stub_manager(self):
        if not self.__stub_manager:
            try:
                self.__stub_manager = StubManager(self.__target,
                                                  loopchain_pb2_grpc.PeerServiceStub,
                                                  conf.GRPC_SSL_TYPE)
            except Exception as e:
                logging.exception(f"Create Peer create stub_manager fail target : {self.__target} \n"
                                  f"exception : {e}")

        return self.__stub_manager

    @property
    def status_update_time(self):
        return self.__status_update_time

    def serialize(self) -> dict:
        return {
            'peer_id': self.__peer_id,
            'group_id': self.__group_id,
            'order': self.__order,
            'target': self.__target,
            'status_update_time': self.__status_update_time.strftime(Peer.STATUS_UPDATE_TIME_FORMAT),
            'status': self.__status
        }

    @staticmethod
    def deserialize(peer_serialized: dict) -> 'Peer':
        peer = Peer(peer_id=peer_serialized['peer_id'],
                    target=peer_serialized['target'],
                    status=peer_serialized['status'],
                    order=peer_serialized['order'])
        peer.__status_update_time = datetime.datetime.strptime(peer_serialized['status_update_time'],
                                                               Peer.STATUS_UPDATE_TIME_FORMAT)
        return peer

    def dump(self) -> bytes:
        serialized = self.serialize()
        return json.dumps(serialized).encode(encoding=conf.PEER_DATA_ENCODING)

    @staticmethod
    def load(peer_dumped: bytes):
        serialized = json.loads(peer_dumped.decode(encoding=conf.PEER_DATA_ENCODING))
        return Peer.deserialize(serialized)
