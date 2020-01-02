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

import os

from loopchain import configure as conf
from loopchain import utils
from loopchain.baseservice import ObjectManager, RestMethod
from loopchain.blockchain.types import Hash32
from loopchain.channel.channel_property import ChannelProperty


class PeerLoader:
    def __init__(self):
        pass

    @staticmethod
    def load():
        peers = PeerLoader._load_peers_from_db()
        if peers:
            utils.logger.info("Reps data loaded from DB")
            return peers
        elif os.path.exists(conf.CHANNEL_MANAGE_DATA_PATH):
            utils.logger.info(f"Try to load reps data from {conf.CHANNEL_MANAGE_DATA_PATH}")
            return PeerLoader._load_peers_from_file()
        else:
            utils.logger.info("Try to load reps data from other reps")
            return PeerLoader._load_peers_from_rest_call()

    @staticmethod
    def _load_peers_from_db() -> list:
        blockchain = ObjectManager().channel_service.block_manager.blockchain
        last_block = blockchain.last_block
        rep_root_hash = (last_block.header.reps_hash if last_block else
                         Hash32.fromhex(conf.CHANNEL_OPTION[ChannelProperty().name].get('crep_root_hash')))

        return blockchain.find_preps_by_roothash(rep_root_hash)

    @staticmethod
    def _load_peers_from_file():
        channel_info = utils.load_json_data(conf.CHANNEL_MANAGE_DATA_PATH)
        reps: list = channel_info[ChannelProperty().name].get("peers")
        return [{"id": rep["id"], "p2pEndpoint": rep["peer_target"]} for rep in reps]

    @staticmethod
    def _load_peers_from_rest_call():
        rs_client = ObjectManager().channel_service.rs_client
        crep_root_hash = conf.CHANNEL_OPTION[ChannelProperty().name].get('crep_root_hash')
        reps = rs_client.call(
            RestMethod.GetReps,
            RestMethod.GetReps.value.params(crep_root_hash)
        )
        return [{"id": rep["address"], "p2pEndpoint": rep["p2pEndpoint"]} for rep in reps]
