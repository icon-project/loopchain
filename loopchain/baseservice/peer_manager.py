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
from typing import Union

import loopchain_pb2

import loopchain.utils as util
from loopchain import configure as conf
from loopchain.baseservice import BroadcastCommand, ObjectManager, StubManager, PeerStatus, PeerObject, PeerInfo
from loopchain.protos import message_code


class PeerListData:
    # Manage PeerList to save DB.
    def __init__(self):
        self.peer_info_list: dict = {}  # { peer_id:PeerInfo }
        self.peer_leader = 0  # leader_order
        self.peer_order_list: dict = {}  # { order:peer_id }

    def serialize(self) -> dict:
        peer_info_list_serialized = {peer_id: peer_info.serialize()
                                     for peer_id, peer_info in self.peer_info_list.items()}

        return {
            'peer_info_list': peer_info_list_serialized,
            'peer_leader': self.peer_leader,
            'peer_order_list': self.peer_order_list
        }

    @staticmethod
    def deserialize(peer_list_data_serialized: dict) -> 'PeerListData':
        peer_info_list = {peer_id: PeerInfo.deserialize(peer_info_serialized)
                          for peer_id, peer_info_serialized in peer_list_data_serialized['peer_info_list'].items()}

        peer_order_list = {int(order): peer_id
                           for order, peer_id in peer_list_data_serialized['peer_order_list'].items()}

        peer_list_data = PeerListData()
        peer_list_data.peer_info_list = peer_info_list
        peer_list_data.peer_leader = peer_list_data_serialized['peer_leader']
        peer_list_data.peer_order_list = peer_order_list
        return peer_list_data

    def dump(self) -> bytes:
        serialized = self.serialize()
        return json.dumps(serialized).encode(encoding=conf.PEER_DATA_ENCODING)

    @staticmethod
    def load(peer_list_data_dumped: bytes):
        serialized = json.loads(peer_list_data_dumped.decode(encoding=conf.PEER_DATA_ENCODING))
        return PeerListData.deserialize(serialized)


class PeerManager:
    def __init__(self, channel_name):
        """DB에서 기존에 생성된 PeerList 를 가져온다.
        이때 peer status 는 unknown 으로 리셋한다.
        """
        self.peer_list_data = PeerListData()
        self.__channel_name = channel_name
        self.peer_object_list = {}

        # lock object for if add new peer don't have order that must locking
        self.__add_peer_lock: threading.Lock = threading.Lock()

        self.__leader_complain_count = 0
        self.__highest_block_height = -1    # for RS heartbeat

    @property
    def peer_list(self) -> dict:
        """

        :return: { peer_id:PeerInfo }
        """
        # util.logger.spam(f"peer_list({self.peer_list_data.peer_info_list})")
        return self.peer_list_data.peer_info_list

    @property
    def peer_order_list(self) -> dict:
        """

        :return: { order:peer_id }
        """
        return self.peer_list_data.peer_order_list

    def set_peer_list(self, peer_list_data: PeerListData):
        """ update PeerList

        :param peer_list_data: PeerListData
        """
        self.peer_list_data = peer_list_data

    def peer_ids_hash(self):
        """ It's temporary develop for Prep test net. This value will replace with Prep root hash.

        :return:
        """
        order_list = list(self.peer_order_list.keys())
        order_list.sort()
        peer_count = len(order_list)
        peer_ids = ""

        for i in range(peer_count):
            peer_order = order_list[i]
            peer_id = self.peer_order_list[peer_order]
            peer_each = self.peer_list[peer_id]

            util.logger.debug(f"peer_order({peer_order}), peer_id({peer_id}), peer_target({peer_each.target})")
            peer_ids += peer_id

        return self.get_peer_ids_hash(peer_ids)

    @staticmethod
    def get_peer_ids_hash(peer_ids):
        peer_ids_hash = hashlib.sha256(peer_ids.encode(encoding='UTF-8')).hexdigest()
        util.logger.debug(f"peer ids hash({peer_ids_hash})")
        return peer_ids_hash

    def get_quorum(self):
        peer_count = self.get_peer_count()
        quorum = math.floor(peer_count * conf.VOTING_RATIO) + 1
        complain_quorum = math.floor(peer_count * (1-conf.VOTING_RATIO)) + 1

        return quorum, complain_quorum

    def get_reps(self):
        peer_ids = (self.peer_order_list[peer_order]
                    for peer_order in sorted(self.peer_order_list.keys()))
        peers = (self.peer_list[peer_id] for peer_id in peer_ids)
        return [{"id": peer.peer_id, "target": peer.target} for peer in peers]

    def get_peer_by_target(self, peer_target):
        return next((peer for peer in self.peer_list.values() if peer.target == peer_target), None)

    def add_peer(self, peer_info: Union[PeerInfo, dict]):
        """add_peer to peer_manager

        :param peer_info: PeerInfo, dict
        :return: create_peer_order
        """

        if isinstance(peer_info, dict):
            peer_info = PeerInfo(peer_info["id"], peer_info["id"], peer_info["peer_target"], order=peer_info["order"])

        logging.debug(f"add peer id: {peer_info.peer_id}")
        peer_object = PeerObject(self.__channel_name, peer_info)

        # add_peer logic must be atomic
        with self.__add_peer_lock:
            if peer_info.order <= 0:
                if peer_info.peer_id in self.peer_list:
                    peer_info.order = self.peer_list[peer_info.peer_id].order
                else:
                    peer_info.order = self.__make_peer_order(peer_info)

            logging.debug(f"new peer order {peer_info.peer_id} : {peer_info.order}")

            # set to leader peer
            if self.peer_list_data.peer_leader == 0 or len(self.peer_list) == 0:
                logging.debug("Set Group Leader Peer: " + str(peer_info.order))
                self.peer_list_data.peer_leader = peer_info.order

            self.peer_list[peer_info.peer_id] = peer_info
            self.peer_order_list[peer_info.order] = peer_info.peer_id
            self.peer_object_list[peer_info.peer_id] = peer_object

        broadcast_scheduler = ObjectManager().channel_service.broadcast_scheduler
        broadcast_scheduler.schedule_job(BroadcastCommand.SUBSCRIBE, peer_info.target)

        return peer_info.order

    def update_peer_status(self, peer_id, peer_status=PeerStatus.connected) -> PeerInfo:
        try:
            peer = self.peer_list[peer_id]
            peer.status = peer_status
            return peer
        except Exception as e:
            logging.warning(f"fail update peer status peer_id({peer_id})")
            logging.warning(f"exception : {e}")

        return None

    def set_leader_peer(self, peer):
        """리더 피어를 지정한다.
        없는 경우에는 전체 리더 피어를 지정하게 된다.

        :param peer: 리더로 지정할 peer 의 정보
        :return:
        """

        if self.get_peer(peer.peer_id) is None:
            self.add_peer(peer)

        self.peer_list_data.peer_leader = peer.order

    def get_leader_peer(self, is_peer=True) -> PeerInfo:
        """

        :return:
        """

        try:
            leader_peer_id = self.get_leader_id()
            if leader_peer_id:
                leader_peer = self.get_peer(leader_peer_id)
                return leader_peer
        except KeyError as e:
            logging.exception(f"peer_manager:get_leader_peer exception({e})")

            if is_peer and ObjectManager().channel_service.is_support_node_function(conf.NodeFunction.Vote):
                util.exit_and_msg(f"Fail to find a leader of this network.... {e}")

        return None

    def get_leader_id(self) -> str or None:
        """get leader's peer id

        :return: leader peer_id
        """
        if not ObjectManager().channel_service.is_support_node_function(conf.NodeFunction.Vote):
            return None

        leader_peer_order = self.peer_list_data.peer_leader
        logging.debug(f"peer_manager:get_leader_id leader peer order {leader_peer_order}")
        # util.logger.spam(f"peer_manager:get_leader_id peer_order_list({self.peer_order_list})")
        try:
            return self.peer_order_list[leader_peer_order]
        except KeyError:
            util.logger.spam(
                f"get_leader_id KeyError leader_peer_order({leader_peer_order})")

        return None

    def get_leader_object(self) -> PeerObject:
        """get leader peer object

        :return: leader peer object
        """

        try:
            leader_id = self.get_leader_id()
            leader_object = self.peer_object_list[leader_id]
            return leader_object
        except KeyError as e:
            raise e

    def get_next_leader_peer(self, current_leader_peer_id=None, is_only_alive=False):
        util.logger.spam(f"peer_manager:get_next_leader_peer current_leader_peer_id({current_leader_peer_id})")

        if not current_leader_peer_id:
            leader_peer = self.get_leader_peer()
        else:
            leader_peer = self.get_peer(current_leader_peer_id)

        return self.__get_next_peer(leader_peer, is_only_alive)

    def __get_next_peer(self, peer, is_only_alive=False):
        if peer is None:
            return None

        order_list = list(self.peer_order_list.keys())
        order_list.sort()

        # logging.debug("order list: " + str(order_list))
        # logging.debug("peer.order: " + str(peer.order))

        peer_order_position = order_list.index(peer.order)
        next_order_position = peer_order_position + 1
        peer_count = len(order_list)

        util.logger.spam(f"peer_manager:__get_next_peer peer_count({peer_count})")

        for i in range(peer_count):
            # Prevent out of range
            if next_order_position >= peer_count:
                next_order_position = 0

            # It doesn't matter that peer status is connected or not, when 'is_only_alive' is false.
            if not is_only_alive:
                break

            peer_order = order_list[next_order_position]
            peer_id = self.peer_order_list[peer_order]
            peer_each = self.peer_list[peer_id]

            # It need to check real time status of peer, if 'is_only_alive' is true and status is connected.
            if is_only_alive and peer_each.status == PeerStatus.connected:

                next_peer_id = self.peer_order_list[order_list[next_order_position]]
                leader_peer = self.peer_list[next_peer_id]
                stub_manager = self.get_peer_stub_manager(leader_peer)

                response = stub_manager.call_in_times(
                    "Request", loopchain_pb2.Message(
                        code=message_code.Request.status,
                        channel=self.__channel_name
                    ), is_stub_reuse=True)

                # If it has no response, increase count of 'next_order_position' for checking next peer.
                if response is not None:
                    break  # LABEL 1

            next_order_position += 1
            util.logger.spam(f"peer_manager:__get_next_peer next_order_position({next_order_position})")

        if next_order_position >= peer_count:
            util.logger.spam(f"peer_manager:__get_next_peer Fail break at LABEL 1")
            next_order_position = 0

        try:
            next_peer_id = self.peer_order_list[order_list[next_order_position]]
            util.logger.debug("peer_manager:__get_next_peer next_leader_peer_id: " + str(next_peer_id))
            return self.peer_list[next_peer_id]
        except (IndexError, KeyError) as e:
            logging.warning(f"peer_manager:__get_next_peer there is no next peer ({e})")
            util.logger.spam(f"peer_manager:__get_next_peer "
                             f"\npeer_id({peer.peer_id}), "
                             f"\npeer_object_list({self.peer_object_list}), "
                             f"\npeer_list({self.peer_list})")
            return None

    def get_peer_stub_manager(self, peer) -> StubManager:
        logging.debug(f"get_peer_stub_manager peer_info : {peer.peer_id}")

        try:
            return self.peer_object_list[peer.peer_id].stub_manager
        except Exception as e:
            logging.debug("try get peer stub except: " + str(e))
            return None

    def complain_leader(self, is_announce=False) -> PeerInfo:
        """When current leader is offline, Find last height alive peer and set as a new leader.

        :param is_announce:
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

    def __find_highest_peer(self) -> PeerInfo:
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

    def check_peer_status(self):
        nonresponse_peer_list = []
        check_leader_peer_count = 0

        for peer_id in list(self.peer_object_list):
            peer_info: PeerInfo = self.peer_list[peer_id]
            stub_manager = self.get_peer_stub_manager(peer_info)
            peer_object: PeerObject = self.peer_object_list[peer_id]

            try:
                response = stub_manager.call(
                    "Request", loopchain_pb2.Message(
                        code=message_code.Request.status,
                        channel=self.__channel_name,
                        message="check peer status by rs",
                        meta=json.dumps({"highest_block_height": self.__highest_block_height})
                    ), is_stub_reuse=True)
                if response.code != message_code.Response.success:
                    raise Exception

                peer_object.no_response_count_reset()
                peer_info.status = PeerStatus.connected
                peer_status = json.loads(response.meta)

                if peer_status["state"] == "BlockGenerate":
                    check_leader_peer_count += 1

                if peer_status["block_height"] >= self.__highest_block_height:
                    self.__highest_block_height = peer_status["block_height"]
            except Exception as e:
                util.apm_event(conf.RADIO_STATION_NAME, {
                    'event_type': 'DisconnectedPeer',
                    'peer_name': conf.PEER_NAME,
                    'channel_name': self.__channel_name,
                    'data': {
                        'message': 'there is disconnected peer gRPC Exception: ' + str(e),
                        'peer_id': peer_info.peer_id}})

                logging.warning("there is disconnected peer peer_id(" + peer_info.peer_id +
                                ") gRPC Exception: " + str(e))
                peer_object.no_response_count_up()

                util.logger.spam(
                    f"peer_manager::check_peer_status "
                    f"peer_id({peer_object.peer_info.peer_id}) "
                    f"no response count up({peer_object.no_response_count})")

                if peer_object.no_response_count >= conf.NO_RESPONSE_COUNT_ALLOW_BY_HEARTBEAT:
                    peer_info.status = PeerStatus.disconnected
                    logging.debug(f"peer status update time: {peer_info.status_update_time}")
                    logging.debug(f"this peer not respond {peer_info.peer_id}")
                    nonresponse_peer_list.append(peer_info)

        logging.info(f"non response peer list : {nonresponse_peer_list}")

    def reset_peers(self, reset_action=None, check_status=True):
        self.__reset_peers_in_group(reset_action, check_status)

    def __reset_peers_in_group(self, reset_action, check_status=True):
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

    def __make_peer_order(self, peer):
        """소속된 그룹과 상관없이 전체 peer 가 순서에 대한 order 값을 가진다.
        이 과정은 중복된 order 발급을 방지하기 위하여 atomic 하여야 한다.

        :param peer:
        :return:
        """
        last_order = 0
        # logging.debug("Peer List is: " + str(self.peer_list))

        # 기존에 등록된 peer_id 는 같은 order 를 재사용한다.

        for peer_id in self.peer_list:
            peer_each = self.peer_list[peer_id]
            logging.debug("peer each: " + str(peer_each))
            last_order = [last_order, peer_each.order][last_order < peer_each.order]

        last_order += 1

        return last_order

    def get_peer(self, peer_id) -> PeerInfo:
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
        self.peer_object_list.pop(peer_id, None)
        if removed_peer:
            self.peer_order_list.pop(removed_peer.order, None)

        return removed_peer

    def remove_peer(self, peer_id):
        logging.debug(f"remove peer : {peer_id}")
        removed_peer = self.__remove_peer_from_group(peer_id)
        if removed_peer:
            util.logger.spam(f"peer_manager:remove_peer try remove audience in sub processes")
            if ObjectManager().rs_service:
                ObjectManager().rs_service.channel_manager.remove_audience(self.__channel_name, removed_peer)
            else:
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

    def get_connected_peer_count(self):
        return sum(
            self.peer_list[peer_id].status == PeerStatus.connected for peer_id in self.peer_list
        )

    def get_peers_for_debug(self):
        peers = ""
        peer_list = []
        try:
            for peer_id in self.peer_list:
                peer_each = self.peer_list[peer_id]
                peer_list.append(peer_each)
                peers += "\n" + (str(peer_each.order) + ":" + peer_each.target
                                 + " " + str(peer_each.status)) + " " + str(peer_id) + " (" + str(type(peer_id)) + ")"
        except KeyError:
            logging.debug("no peer list")

        return peers, peer_list

    def peer_list_full_print_out_for_debug(self):
        """peer list 의 data 목록을 전체 출력한다.
        디버깅을 위한 함수로 필요한 구간에서만 호출한 후 제거할 것

        """
        peer_list = self.peer_list
        logging.warning("peer_list: " + str(peer_list.items()))
        peer_leader = self.peer_list_data.peer_leader
        logging.warning("peer_leader: " + str(peer_leader))
        peer_order_list = self.peer_order_list
        logging.warning("peer_order_list: " + str(peer_order_list.items()))

        for peer_id in peer_list:
            peer_each = peer_list[peer_id]
            logging.warning("peer_each: " + str(peer_each))
            # peer_each.dump()

    def get_IP_of_peers_in_group(self, status=None):
        """

        :param status: peer online status
        :return: peer들의 IP들의 list.
        """
        ip_list = []
        for peer_id in self.peer_list:
            peer_each = self.peer_list[peer_id]
            if status is None or status == peer_each.status:
                ip_list.append(str(peer_each.order)+":"+peer_each.target)

        return ip_list

    def get_IP_of_peers_dict(self):
        return {peer_id: peer.target for peer_id, peer in self.peer_list.items()}
