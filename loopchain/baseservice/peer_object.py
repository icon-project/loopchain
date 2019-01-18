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
import logging
from enum import IntEnum

from loopchain import configure as conf
from loopchain.baseservice import StubManager
from loopchain.protos import loopchain_pb2_grpc


class PeerStatus(IntEnum):
    unknown = 0
    connected = 1
    disconnected = 2


class PeerInfo:
    """Peer Object"""

    def __init__(self, peer_id: str, group_id: str,
                 target: str = "", status: PeerStatus = PeerStatus.unknown, order: int = 0):
        """ create PeerInfo
        if connected peer status PeerStatus.connected

        :param peer_id: peer_id
        :param group_id: peer's group_id
        :param target: grpc target info default ""
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
    def status_update_time(self):
        return self.__status_update_time


class PeerObject:
    """Peer object has PeerInfo and live data"""

    def __init__(self, channel: str, peer_info: PeerInfo):
        """set peer info and create live data

        :param channel: peer channel name
        :param peer_info: peer info
        """
        self.__peer_info: PeerInfo = peer_info
        self.__stub_manager: StubManager = None
        self.__cert_verifier = None
        self.__no_response_count = 0
        self.__channel = channel

        self.__create_live_data()

    def __create_live_data(self):
        try:
            self.__stub_manager = StubManager(self.__peer_info.target,
                                              loopchain_pb2_grpc.PeerServiceStub,
                                              conf.GRPC_SSL_TYPE)
        except Exception as e:
            logging.exception(f"Create Peer create stub_manager fail target : {self.__peer_info.target} \n"
                              f"exception : {e}")

    @property
    def peer_info(self)-> PeerInfo:
        return self.__peer_info

    @property
    def stub_manager(self) -> StubManager:
        return self.__stub_manager

    @property
    def no_response_count(self):
        return self.__no_response_count

    @property
    def channel(self):
        return self.__channel

    def no_response_count_up(self):
        self.__no_response_count += 1

    def no_response_count_reset(self):
        self.__no_response_count = 0
