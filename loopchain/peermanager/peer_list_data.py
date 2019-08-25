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
"""A module for managing peer list"""

import json
from collections import OrderedDict
from typing import TYPE_CHECKING, Optional

import loopchain.utils as util
from loopchain import configure as conf
from loopchain.peermanager import Peer

if TYPE_CHECKING:
    from loopchain.blockchain.blocks import BlockHeader


class PeerListData:
    """Manage peer list as serializable data."""
    def __init__(self):
        self.peer_list: OrderedDict[BlockHeader.peer_id, Peer] = OrderedDict()  # { peer_id:Peer }
        self.leader_id: BlockHeader.peer_id = None  # leader_peer_id

    def serialize(self) -> dict:
        peer_list_serialized = [peer.serialize() for peer_id, peer in self.peer_list.items()]

        return {
            'peer_list': peer_list_serialized,
            'leader_id': self.leader_id
        }

    @staticmethod
    def deserialize(peer_list_data_serialized: dict) -> 'PeerListData':
        peers_as_list = [Peer.deserialize(peer_serialized)
                         for peer_id, peer_serialized in peer_list_data_serialized['peer_list']]
        sorted(peers_as_list, key=lambda peer: peer.order)

        peer_list = OrderedDict([(peer.peer_id, peer) for peer in peers_as_list])

        peer_list_data = PeerListData()
        peer_list_data.peer_list = peer_list
        peer_list_data.leader_id = peer_list_data_serialized['leader_id']
        return peer_list_data

    def dump(self) -> bytes:
        serialized = self.serialize()
        return json.dumps(serialized).encode(encoding=conf.PEER_DATA_ENCODING)

    @staticmethod
    def load(peer_list_data_dumped: bytes):
        serialized = json.loads(peer_list_data_dumped.decode(encoding=conf.PEER_DATA_ENCODING))
        return PeerListData.deserialize(serialized)

    def next_peer(self, peer_id) -> Optional[Peer]:
        try:
            return list(self.peer_list.values())[list(self.peer_list.keys()).index(peer_id) + 1]
        except IndexError:
            util.logger.notice(
                f"there is no peer_id({peer_id}) set index[0] peer({list(self.peer_list.values())[0]}) to leader")
            return list(self.peer_list.values())[0]
        except ValueError:
            util.logger.warning(f"peer_id({peer_id}) not in peer_list")
            return None

    def last_peer(self) -> Optional[Peer]:
        """get last peer in peer_list

        :return:
        """
        if len(self.peer_list) > 0:
            return list(self.peer_list.values())[-1]
        return None
