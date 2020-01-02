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
"""A module for managing peer list"""

import threading
from typing import Optional, Union

import loopchain.utils as util
from loopchain.baseservice import ObjectManager
from loopchain.blockchain.blocks import BlockProverType
from loopchain.blockchain.blocks.v0_3 import BlockProver
from loopchain.blockchain.types import ExternalAddress, Hash32
from loopchain.channel.channel_property import ChannelProperty
from loopchain.configure_default import NodeType
from loopchain.peermanager import Peer, PeerLoader, PeerListData


class PeerManager:
    def __init__(self):
        """Manage peer list in operation."""

        self._peer_list_data = PeerListData()

        # lock object for if add new peer don't have order that must locking
        self.__add_peer_lock: threading.Lock = threading.Lock()

        # reps_hash, reps for reset_all_peers
        self._reps_reset_data: Optional[tuple] = None

        self._prepared_reps_hash = None

    @property
    def prepared_reps_hash(self):
        return self._prepared_reps_hash

    def reps_hash(self) -> Hash32:
        """return reps root hash.

        :return:
        """
        block_prover = BlockProver((ExternalAddress.fromhex_address(peer.peer_id).extend()
                                    for peer in self._peer_list_data.peer_list.values()),
                                   BlockProverType.Rep)
        return block_prover.get_proof_root()

    def serialize_as_preps(self) -> list:
        return [{'id': peer_id, 'p2pEndpoint': peer.target}
                for peer_id, peer in self._peer_list_data.peer_list.items()]

    def load_peers(self) -> None:
        reps = PeerLoader.load()
        util.logger.info(f"Initial Loaded Reps: {reps}")
        for order, rep_info in enumerate(reps, 1):
            peer = Peer(rep_info['id'], rep_info['p2pEndpoint'], order=order)
            self.add_peer(peer)

        blockchain = ObjectManager().channel_service.block_manager.blockchain
        reps_hash = self.reps_hash()
        reps_in_db = blockchain.find_preps_by_roothash(reps_hash)

        if not reps_in_db:
            preps = self.serialize_as_preps()
            util.logger.spam(f"in _load_peers serialize_as_preps({preps})")
            blockchain.write_preps(reps_hash, preps)

    def add_peer(self, peer: Union[Peer, dict]):
        """add_peer to peer_manager

        :param peer: Peer, dict
        :return: create_peer_order
        """

        if isinstance(peer, dict):
            peer = Peer(peer["id"], peer["peer_target"], order=peer["order"])

        util.logger.debug(f"add peer id: {peer.peer_id}")

        # add_peer logic must be atomic
        with self.__add_peer_lock:
            last_peer = self._peer_list_data.last_peer()
            if last_peer and peer.order <= last_peer.order:
                util.logger.warning(f"Fail add peer order({peer.order}), last peer order({last_peer.order})"
                                    f"\npeers({self._peer_list_data.peer_list})")
                return None

            self._peer_list_data.peer_list[peer.peer_id] = peer
            self._prepared_reps_hash = self.reps_hash()

        return peer.order

    def reset_all_peers(self, reps_hash, reps, update_now=True):
        util.logger.debug(
            f"reset_all_peers."
            f"\nresult roothash({reps_hash})"
            f"\npeer_list roothash({self.reps_hash().hex()})"
            f"\nupdate now({update_now})")

        if not update_now:
            self._reps_reset_data = (reps_hash, reps)
            return

        blockchain = ObjectManager().channel_service.block_manager.blockchain

        if reps_hash == self.reps_hash().hex():
            util.logger.debug(f"There is no change in reps.")
            return

        self._peer_list_data.peer_list.clear()
        self._prepared_reps_hash = None

        for order, rep_info in enumerate(reps, 1):
            peer = Peer(rep_info["id"], rep_info["p2pEndpoint"], order=order)
            self.add_peer(peer)

        new_reps = blockchain.find_preps_addresses_by_roothash(Hash32.fromhex(reps_hash, ignore_prefix=True))
        new_node_type = NodeType.CommunityNode if ChannelProperty().peer_address in new_reps else NodeType.CitizenNode
        is_switched_role = new_node_type != ChannelProperty().node_type
        blockchain.reset_leader_made_block_count(is_switched_role)

    def update_all_peers(self):
        if self._reps_reset_data:
            self.reset_all_peers(*self._reps_reset_data, update_now=True)
            self._reps_reset_data = None
