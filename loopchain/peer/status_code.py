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
""" A massage class for the loopchain """

from enum import IntEnum

from loopchain.protos import loopchain_pb2


class Service(IntEnum):
    # Service state Code >= 0 : Service available states
    online = 0
    peer_type_peer = loopchain_pb2.PEER  # 0
    peer_type_leader = loopchain_pb2.BLOCK_GENERATOR  # 1
    peer_type_rs = loopchain_pb2.RADIO_STATION  # 2
    peer_type_community = loopchain_pb2.CommunityNode  # 3
    peer_type_citizen = loopchain_pb2.CitizenNode  # 1

    # Service state Code < 0 : Service not available states
    block_height_sync = -100
    mq_down = -200


__StatusReasonMap = {
    Service.online: str(Service.online),
    Service.peer_type_peer: str(Service.peer_type_peer),
    Service.peer_type_leader: str(Service.peer_type_leader),
    Service.peer_type_rs: str(Service.peer_type_rs),
    Service.peer_type_community: str(Service.peer_type_community),
    Service.peer_type_citizen: str(Service.peer_type_citizen),
    Service.block_height_sync: "block height sync",
    Service.mq_down: "mq down"
}


def get_status_reason(status):
    return __StatusReasonMap[status]
