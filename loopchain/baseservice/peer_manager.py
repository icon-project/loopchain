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

import hashlib
import json
import logging
import math
import threading
from collections import OrderedDict
from typing import TYPE_CHECKING, Optional
from typing import Union, cast

import loopchain_pb2

import loopchain.utils as util
from loopchain import configure as conf
from loopchain.baseservice import BroadcastCommand, ObjectManager, StubManager, Peer
from loopchain.channel.channel_property import ChannelProperty
from loopchain.utils.icon_service import convert_params, ParamType, response_to_json_query
from loopchain.utils.message_queue import StubCollection

if TYPE_CHECKING:
    from loopchain.blockchain.blocks import BlockHeader


class PeerListData:
    """Manage peer list as serializable data."""
    def __init__(self):
        self.peer_list: OrderedDict[BlockHeader.peer_id, Peer] = OrderedDict()  # { peer_id:Peer }
        self.leader_id: BlockHeader.peer_id = None  # leader_peer_id

    def serialize(self) -> dict:
        peer_list_serialized = {peer_id: peer.serialize()
                                for peer_id, peer in self.peer_list.items()}

        return {
            'peer_list': peer_list_serialized,
            'leader_id': self.leader_id
        }

    @staticmethod
    def deserialize(peer_list_data_serialized: dict) -> 'PeerListData':
        peer_list = {peer_id: Peer.deserialize(peer_serialized)
                     for peer_id, peer_serialized in peer_list_data_serialized['peer_list'].items()}

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
            return list(self.peer_list.values())[0]
        except ValueError:
            util.logger.warning(f"peer_id({peer_id}) not in peer_list")
            return None


class PeerManager:
    def __init__(self):
        """Manage peer list in operation."""
        self.peer_list_data = PeerListData()

        # lock object for if add new peer don't have order that must locking
        self.__add_peer_lock: threading.Lock = threading.Lock()

    @property
    def peer_list(self) -> dict:
        """

        :return: { peer_id:PeerInfo }
        """
        return self.peer_list_data.peer_list

    def get_peer_last(self) -> Optional[Peer]:
        """get last peer in peer_list

        :return:
        """
        peer_list = list(self.peer_list_data.peer_list.values())
        if len(peer_list) > 0:
            return peer_list[-1]
        return None

    def peer_ids_hash(self):
        """ It's temporary develop for Prep test net. This value will replace with Prep root hash.

        :return:
        """
        peer_ids = ""

        for peer in self.peer_list.values():

            util.logger.debug(f"peer_order({peer.order}), peer_id({peer.peer_id}), peer_target({peer.target})")
            peer_ids += peer.peer_id

        return self.get_peer_ids_hash(peer_ids)

    @staticmethod
    def get_peer_ids_hash(peer_ids):
        peer_ids_hash = hashlib.sha256(peer_ids.encode(encoding='UTF-8')).hexdigest()
        util.logger.debug(f"peer ids hash({peer_ids_hash})")
        return peer_ids_hash

    def load_peers_from_iiss(self):
        request = {
            "method": "ise_getPRepList"
        }

        request = convert_params(request, ParamType.call)
        stub = StubCollection().icon_score_stubs[ChannelProperty().name]
        response = cast(dict, stub.sync_task().call(request))
        response_to_json_query(response)

        util.logger.debug(f"in load_peers_from_iiss response({response})")
        if 'preps' not in response['result']:
            util.logger.debug(f"There is no preps in result.")
            return

        util.logger.notice(f"load_peers_from_iiss "
                           f"reps_root_hash({response['result']['rootHash']}) and "
                           f"peer_ids_hash({self.peer_ids_hash()})")
        if response["result"]["rootHash"] == self.peer_ids_hash():
            util.logger.debug(f"There is no change in peers.")
            return

        if not conf.LOAD_PEERS_FROM_IISS:
            return

        self.reset_peers(check_status=False)

        reps = response["result"]["preps"]
        self._add_reps(reps)

    async def load_peers_from_file(self):
        util.logger.notice(f"load_peers_from_file")
        channel_info = util.load_json_data(conf.CHANNEL_MANAGE_DATA_PATH)
        reps: list = channel_info[ChannelProperty().name].get("peers")
        for peer in reps:
            self.add_peer(peer)

    async def load_peers_from_rest_call(self):
        # FIXME temporarily disable GetReps API for legacy support
        # response = ObjectManager().channel_service.radio_station_stub.call("GetReps")
        # reps = response.get('rep')
        # self._add_reps(reps)
        response = ObjectManager().channel_service.radio_station_stub.call("GetChannelInfos")
        reps: list = response['channel_infos'][ChannelProperty().name].get('peers')
        for peer_info in reps:
            self.add_peer(peer_info)

    def _add_reps(self, reps: list):
        for order, rep_info in enumerate(reps, 1):
            peer = Peer(rep_info["id"], rep_info["p2pEndpoint"], order=order)
            self.add_peer(peer)

    def show_peers(self):
        util.logger.debug(f"peer_service:show_peers ({ChannelProperty().name}): ")
        for peer_id in list(self.peer_list):
            peer = self.peer_list[peer_id]
            util.logger.debug(f"peer_target: {peer.order}:{peer.target}")

    def get_quorum(self):
        peer_count = self.get_peer_count()
        quorum = math.floor(peer_count * conf.VOTING_RATIO) + 1
        complain_quorum = math.floor(peer_count * (1-conf.VOTING_RATIO)) + 1

        return quorum, complain_quorum

    def get_reps(self):
        return [{"id": peer.peer_id, "target": peer.target} for peer in self.peer_list.values()]

    def get_peer_by_target(self, peer_target):
        return next((peer for peer in self.peer_list.values() if peer.target == peer_target), None)

    def add_peer(self, peer: Union[Peer, dict]):
        """add_peer to peer_manager

        :param peer: Peer, dict
        :return: create_peer_order
        """

        if isinstance(peer, dict):
            peer = Peer(peer["id"], peer["peer_target"], order=peer["order"])

        logging.debug(f"add peer id: {peer.peer_id}")

        # add_peer logic must be atomic
        with self.__add_peer_lock:
            last_peer = self.get_peer_last()
            if last_peer and peer.order <= last_peer.order:
                util.logger.warning(f"Fail add peer order({peer.order}), last peer order({last_peer.order})"
                                    f"\npeers({self.peer_list_data.peer_list})")
                return None

            # set to leader peer
            if not self.peer_list_data.leader_id or len(self.peer_list) == 0:
                logging.debug("Set Group Leader Peer: " + str(peer.order))
                self.peer_list_data.leader_id = peer.peer_id

            self.peer_list[peer.peer_id] = peer

        broadcast_scheduler = ObjectManager().channel_service.broadcast_scheduler
        broadcast_scheduler.schedule_job(BroadcastCommand.SUBSCRIBE, peer.target)

        return peer.order

    def set_leader_peer(self, peer):
        """리더 피어를 지정한다.
        없는 경우에는 전체 리더 피어를 지정하게 된다.

        :param peer: 리더로 지정할 peer 의 정보
        :return:
        """

        if self.get_peer(peer.peer_id) is None:
            self.add_peer(peer)

        self.peer_list_data.leader_id = peer.peer_id

    def get_leader_peer(self, is_peer=True) -> Optional[Peer]:
        """

        :return:
        """

        leader_peer = self.get_peer(self.peer_list_data.leader_id)
        if not leader_peer and is_peer and \
                ObjectManager().channel_service.is_support_node_function(conf.NodeFunction.Vote):
            util.exit_and_msg(f"Fail to find a leader of this network!")

        return leader_peer

    def get_leader_id(self) -> Optional[str]:
        """get leader's peer id

        :return: leader peer_id
        """
        if not ObjectManager().channel_service.is_support_node_function(conf.NodeFunction.Vote):
            return None

        return self.peer_list_data.leader_id

    def get_next_leader_peer(self, current_leader_peer_id=None):
        util.logger.spam(f"peer_manager:get_next_leader_peer current_leader_peer_id({current_leader_peer_id})")

        if not current_leader_peer_id:
            leader_peer = self.get_leader_peer()
        else:
            leader_peer = self.get_peer(current_leader_peer_id)

        return self.peer_list_data.next_peer(leader_peer.peer_id)

    def get_peer_stub_manager(self, peer) -> Optional[StubManager]:
        logging.debug(f"get_peer_stub_manager peer_id : {peer.peer_id}")

        try:
            return self.peer_list[peer.peer_id].stub_manager
        except Exception as e:
            logging.debug("try get peer stub except: " + str(e))
            return None

    def complain_leader(self) -> Peer:
        """When current leader is offline, Find last height alive peer and set as a new leader.

        :return:
        """

        leader_peer = self.get_leader_peer(is_peer=False)
        try:
            stub_manager = self.get_peer_stub_manager(leader_peer)
            response = stub_manager.call("GetStatus", loopchain_pb2.StatusRequest(request=""), is_stub_reuse=True)

            status_json = json.loads(response.status)
            logging.warning(f"stub_manager target({stub_manager.target}) type({status_json['peer_type']})")

            if status_json["peer_type"] == str(loopchain_pb2.BLOCK_GENERATOR):
                return leader_peer
            else:
                raise Exception
        except Exception as e:
            new_leader = self.__find_highest_peer()
            if new_leader is not None:
                # 변경된 리더를 announce 해야 한다
                logging.warning("Change peer to leader that complain old leader.")
                self.set_leader_peer(new_leader)
        return new_leader

    def __find_highest_peer(self) -> Peer:
        # 강제로 list 를 적용하여 값을 복사한 다음 사용한다. (중간에 값이 변경될 때 발생하는 오류를 방지하기 위해서)
        most_height = 0
        most_height_peer = None
        for peer_id in list(self.peer_list):
            peer_each = self.peer_list[peer_id]
            stub_manager = peer_each.stub_manager
            try:
                response = stub_manager.call("GetStatus",
                                             loopchain_pb2.StatusRequest(request="find highest peer"),
                                             is_stub_reuse=True)

                peer_status = json.loads(response.status)
                if int(peer_status["block_height"]) >= most_height:
                    most_height = int(peer_status["block_height"])
                    most_height_peer = peer_each
            except Exception as e:
                logging.warning("gRPC Exception: " + str(e))

        return most_height_peer

    def reset_peers(self, reset_action=None, check_status=True):
        # 강제로 list 를 적용하여 값을 복사한 다음 사용한다. (중간에 값이 변경될 때 발생하는 오류를 방지하기 위해서)
        for peer_id in list(self.peer_list):
            peer_each = self.peer_list[peer_id]

            do_remove_peer = False

            if check_status:
                try:
                    stub_manager = self.get_peer_stub_manager(peer_each)
                    stub_manager.call("GetStatus", loopchain_pb2.StatusRequest(request="reset peers in group"),
                                      is_stub_reuse=True)
                except Exception as e:
                    logging.warning(f"gRPC Exception({str(e)}) remove this peer({str(peer_each.target)})")
                    do_remove_peer = True
            else:
                do_remove_peer = True

            if do_remove_peer:
                self.remove_peer(peer_each.peer_id)
                if reset_action is not None:
                    reset_action(peer_each.peer_id, peer_each.target)

    def get_peer(self, peer_id) -> Optional[Peer]:
        """peer_id 에 해당하는 peer 를 찾는다.

        :param peer_id:
        :return:
        """

        try:
            if not isinstance(peer_id, str):
                logging.error("peer_id type is: " + str(type(peer_id)) + ":" + str(peer_id))

            return self.peer_list[str(peer_id)]

        except KeyError:
            if ObjectManager().channel_service.is_support_node_function(conf.NodeFunction.Vote):
                logging.warning("there is no peer by id: " + str(peer_id))
                logging.debug(self.get_peers_for_debug())
                return None
            else:
                logging.debug(f"This node({peer_id}) will run as {conf.NodeType.CitizenNode.name}")
                return None
        except IndexError:
            logging.warning(f"there is no peer by id({str(peer_id)})")
            logging.debug(self.get_peers_for_debug())
            return None

    def __remove_peer_from_group(self, peer_id):
        removed_peer = self.peer_list.pop(peer_id, None)
        return removed_peer

    def remove_peer(self, peer_id):
        logging.debug(f"remove peer : {peer_id}")
        removed_peer = self.__remove_peer_from_group(peer_id)
        if removed_peer:
            util.logger.spam(f"peer_manager:remove_peer try remove audience in sub processes")
            broadcast_scheduler = ObjectManager().channel_service.broadcast_scheduler
            broadcast_scheduler.schedule_job(BroadcastCommand.UNSUBSCRIBE, removed_peer.target)
            return True

        return False

    def get_peer_count(self):
        count = 0
        try:
            count = len(self.peer_list)
        except KeyError:
            logging.debug("no peer list")

        return count

    def get_peers_for_debug(self):
        peers = ""
        peer_list = []
        try:
            for peer_id in self.peer_list:
                peer_each = self.peer_list[peer_id]
                peer_list.append(peer_each)
                peers += "\n" + str(peer_each.order) + ":" + peer_each.target \
                         + " " + str(peer_id) + " (" + str(type(peer_id)) + ")"
        except KeyError:
            logging.debug("no peer list")

        return peers, peer_list
