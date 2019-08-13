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
from typing import TYPE_CHECKING
from typing import cast

from loopchain import configure as conf
from loopchain import utils
from loopchain.baseservice import ObjectManager
from loopchain.channel.channel_property import ChannelProperty
from loopchain.peermanager import Peer
from loopchain.utils.icon_service import convert_params, ParamType, response_to_json_query
from loopchain.utils.message_queue import StubCollection

if TYPE_CHECKING:
    from loopchain.peermanager import PeerManager


class PeerLoader:
    def __init__(self):
        pass

    @staticmethod
    async def load(peer_manager: 'PeerManager'):
        PeerLoader.load_peers_from_iiss(peer_manager)

        if not peer_manager.peer_list:
            if conf.NodeType.is_support_node_function(conf.NodeFunction.Vote, ChannelProperty().node_type):
                await PeerLoader._load_peers_from_file(peer_manager)
            else:
                await PeerLoader._load_peers_from_rest_call(peer_manager)

        utils.logger.debug(f"peer_service:show_peers ({ChannelProperty().name}): ")
        for peer_id in list(peer_manager.peer_list):
            peer = peer_manager.peer_list[peer_id]
            utils.logger.debug(f"peer_target: {peer.order}:{peer.target}")

    @staticmethod
    def load_peers_from_iiss(peer_manager: 'PeerManager'):
        request = {
            "method": "ise_getPRepList"
        }

        request = convert_params(request, ParamType.call)
        stub = StubCollection().icon_score_stubs[ChannelProperty().name]
        response = cast(dict, stub.sync_task().call(request))
        response_to_json_query(response)

        utils.logger.debug(f"in load_peers_from_iiss response({response})")
        if 'preps' not in response['result']:
            utils.logger.debug(f"There is no preps in result.")
            return

        if response["result"]["rootHash"] == peer_manager.reps_hash().hex_0x():
            utils.logger.debug(f"There is no change in load_peers_from_iiss.")
            return

        utils.logger.debug(f"There is change in load_peers_from_iiss."
                          f"\nresult roothash({response['result']['rootHash']})"
                          f"\npeer_list roothash({peer_manager.reps_hash().hex_0x()})")

        peer_manager.remove_all_peers()

        reps = response["result"]["preps"]
        for order, rep_info in enumerate(reps, 1):
            peer = Peer(rep_info["id"], rep_info["p2pEndpoint"], order=order)
            peer_manager.add_peer(peer)

    @staticmethod
    async def _load_peers_from_file(peer_manager: 'PeerManager'):
        utils.logger.debug(f"load_peers_from_file")
        channel_info = utils.load_json_data(conf.CHANNEL_MANAGE_DATA_PATH)
        reps: list = channel_info[ChannelProperty().name].get("peers")
        for peer in reps:
            peer_manager.add_peer(peer)

    @staticmethod
    async def _load_peers_from_rest_call(peer_manager: 'PeerManager'):
        rest_stub = ObjectManager().channel_service.radio_station_stub
        if conf.CREP_ROOT_HASH:
            reps = rest_stub.call(
                "GetReps",
                {"repsHash": conf.CREP_ROOT_HASH}
            )
            logging.debug(f"reps by c-rep root hash: {reps}")
            for order, rep_info in enumerate(reps, 1):
                peer = Peer(rep_info["address"], rep_info["p2pEndpoint"], order=order)
                peer_manager.add_peer(peer)
            return

        response = rest_stub.call("GetChannelInfos")
        reps: list = response['channel_infos'][ChannelProperty().name].get('peers')
        for peer_info in reps:
            peer_manager.add_peer(peer_info)
