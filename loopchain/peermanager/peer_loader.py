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
"""PeerListData Loader for PeerManager"""

import logging
import os
from typing import TYPE_CHECKING

from loopchain import configure as conf
from loopchain import utils
from loopchain.baseservice import ObjectManager, RestMethod
from loopchain.channel.channel_property import ChannelProperty
from loopchain.peermanager import Peer

if TYPE_CHECKING:
    from loopchain.peermanager import PeerManager


class PeerLoader:
    def __init__(self):
        pass

    @staticmethod
    def load(peer_manager: 'PeerManager'):
        if os.path.exists(conf.CHANNEL_MANAGE_DATA_PATH):
            PeerLoader._load_peers_from_file(peer_manager)
        else:
            PeerLoader._load_peers_from_rest_call(peer_manager)

    @staticmethod
    def _load_peers_from_file(peer_manager: 'PeerManager'):
        utils.logger.debug(f"load_peers_from_file")
        channel_info = utils.load_json_data(conf.CHANNEL_MANAGE_DATA_PATH)
        reps: list = channel_info[ChannelProperty().name].get("peers")
        for peer in reps:
            peer_manager.add_peer(peer)

    @staticmethod
    def _load_peers_from_rest_call(peer_manager: 'PeerManager'):
        rs_client = ObjectManager().channel_service.rs_client
        crep_root_hash = conf.CHANNEL_OPTION[ChannelProperty().name].get('crep_root_hash')

        if not crep_root_hash:
            logging.error(f"There's no crep_root_hash to initialize.")
            return

        return PeerLoader._get_reps_by_root_hash_call(peer_manager, rs_client, crep_root_hash)

    @staticmethod
    def _get_reps_by_root_hash_call(peer_manager, rs_client, crep_root_hash):
        reps = rs_client.call(
            RestMethod.GetReps,
            RestMethod.GetReps.value.params(crep_root_hash)
        )
        logging.debug(f"reps by c-rep root hash: {reps}")
        for order, rep_info in enumerate(reps, 1):
            peer = Peer(rep_info["address"], rep_info["p2pEndpoint"], order=order)
            peer_manager.add_peer(peer)
