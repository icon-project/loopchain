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
""" A class for gRPC service of Radio station """

import json
import logging
import threading

import loopchain_pb2

import loopchain.utils as util
from loopchain import configure as conf
from loopchain.baseservice import (PeerStatus, PeerInfo, PeerListData, PeerManager,
                                   ObjectManager, TimerService, Timer)
from loopchain.configure_default import KeyLoadType
from loopchain.protos import loopchain_pb2_grpc, message_code


class OuterService(loopchain_pb2_grpc.RadioStationServicer):
    """Radiostation의 gRPC service를 구동하는 Class."""

    def __init__(self):
        self.__handler_map = {
            message_code.Request.status: self.__handler_status,
            message_code.Request.peer_get_leader: self.__handler_get_leader_peer,
            message_code.Request.peer_complain_leader: self.__handler_complain_leader,
            message_code.Request.rs_set_configuration: self.__handler_set_configuration,
            message_code.Request.rs_get_configuration: self.__handler_get_configuration
        }

        self.__load_peer_manager_lock: threading.Lock = threading.Lock()

    def __handler_status(self, request, context):
        return loopchain_pb2.Message(code=message_code.Response.success)

    def __handler_get_leader_peer(self, request, context):
        """Get Leader Peer

        :param request: proto.Message {message=group_id}
        :param context:
        :return: proto.Message {object=leader_peer_object}
        """
        channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL if not request.channel else request.channel
        leader_peer: PeerInfo = ObjectManager().rs_service.channel_manager.get_peer_manager(
            channel_name).get_leader_peer(is_peer=False)
        if leader_peer is not None:
            logging.debug(f"leader_peer ({leader_peer.peer_id})")
            peer_dumped = leader_peer.dump()

            return loopchain_pb2.Message(code=message_code.Response.success, object=peer_dumped)

        return loopchain_pb2.Message(code=message_code.Response.fail_no_leader_peer)

    def __handler_complain_leader(self, request, context):
        """Complain Leader Peer

        :param request: proto.Message {message=group_id}
        :param context:
        :return: proto.Message {object=leader_peer_object}
        """

        # 현재 leader peer status 확인 후 맞으면 peer id 를
        # 아니면 complain 한 peer 로 leader 를 변경 후 응답한다.

        # 선택된 peer 가 leader 로 동작하고 있는지 확인 후 지정하는데 만약
        # get_leader_peer 한 내용과 다르면 AnnounceNewLeader 를 broadcast 하여야 한다.

        logging.debug("in complain leader (radiostation)")
        leader_peer: PeerInfo = ObjectManager().rs_service.channel_manager.get_peer_manager(
            conf.LOOPCHAIN_DEFAULT_CHANNEL).complain_leader()
        if leader_peer is not None:
            logging.warning(f"leader_peer after complain({leader_peer.peer_id})")
            peer_dumped = leader_peer.dump()
            return loopchain_pb2.Message(code=message_code.Response.success, object=peer_dumped)

        return loopchain_pb2.Message(code=message_code.Response.fail_no_leader_peer)

    def __handler_get_configuration(self, request, context):
        """Get Configuration

        :param request: proto.Message {meta=configuration_name}
        :param context:
        :return: proto.Message {meta=configuration_info(s)}
        """

        if request.meta == '':
            result = conf.get_all_configurations()
        else:
            meta = json.loads(request.meta)
            conf_name = meta['name']
            result = conf.get_configuration(conf_name)

        if result is None:
            return loopchain_pb2.Message(
                code=message_code.Response.fail,
                message="'" + conf_name + "' is an incorrect configuration name."
            )
        else:
            json_result = json.dumps(result)
            return loopchain_pb2.Message(
                code=message_code.Response.success,
                meta=json_result
            )

    def __handler_set_configuration(self, request, context):
        """Set Configuration

        :param request: proto.Message {meta=configuration_info}
        :param context:
        :return: proto.Message
        """

        meta = json.loads(request.meta)

        if conf.set_configuration(meta['name'], meta['value']):
            return loopchain_pb2.Message(code=message_code.Response.success)
        else:
            return loopchain_pb2.Message(
                code=message_code.Response.fail,
                message='"' + meta['name'] + '" does not exist in the loopchain configuration list.'
            )

    def Request(self, request, context):
        logging.debug(f"rs_outer_service:Request({request})")

        if request.code in self.__handler_map.keys():
            return self.__handler_map[request.code](request, context)

        return loopchain_pb2.Message(code=message_code.Response.not_treat_message_code)

    def GetStatus(self, request, context):
        """RadioStation의 현재 상태를 요청한다.

        :param request:
        :param context:
        :return:
        """

        logging.debug("RadioStation GetStatus : %s", request)
        status_data = {
            "status": "Service is online: 2",
            "peer_type": "2",
            "audience_count": "0",
            "consensus": str(conf.CONSENSUS_ALGORITHM.name),
            "peer_id": None,
            "block_height": 0,
            "total_tx": 0,
            "peer_target": None
        }

        return loopchain_pb2.StatusReply(
            status=json.dumps(status_data),
            block_height=status_data["block_height"],
            total_tx=status_data["total_tx"])

    def Stop(self, request, context):
        """RadioStation을 종료한다.

        :param request: StopRequest
        :param context:
        :return: StopReply
        """
        logging.info('RadioStation will stop... by: ' + request.reason)
        ObjectManager().rs_service.common_service.stop()
        return loopchain_pb2.StopReply(status="0")

    def GetChannelInfos(self, request: loopchain_pb2.GetChannelInfosRequest, context):
        """Return channels by peer target

        :param request:
        :param context:
        :return:
        """
        if conf.ENABLE_CHANNEL_AUTH:
            channel_infos: str = \
                ObjectManager().rs_service.admin_manager.get_channel_infos_by_peer_target(request.peer_target)
        else:
            channel_infos: str = ObjectManager().rs_service.admin_manager.get_all_channel_info()
        logging.info(f"rs_outer_service:GetChannelInfos target({request.peer_target}) channel_infos({channel_infos})")

        return loopchain_pb2.GetChannelInfosReply(
            response_code=message_code.Response.success,
            channel_infos=channel_infos
        )

    def ConnectPeer(self, request: loopchain_pb2.ConnectPeerRequest, context):
        """RadioStation 에 접속한다. 응답으로 기존의 접속된 Peer 목록을 받는다.

        :param request: PeerRequest
        :param context:
        :return: ConnectPeerReply
        """
        logging.info(f"Trying to connect peer: {request.peer_id}")

        if conf.ENABLE_RADIOSTATION_HEARTBEAT:
            timer_key = f"{TimerService.TIMER_KEY_RS_HEARTBEAT}_{request.channel}"
            if timer_key not in ObjectManager().rs_service.timer_service.timer_list:
                ObjectManager().rs_service.timer_service.add_timer(
                    timer_key,
                    Timer(
                        target=timer_key,
                        duration=conf.SLEEP_SECONDS_IN_RADIOSTATION_HEARTBEAT,
                        is_repeat=True,
                        callback=ObjectManager().rs_service.check_peer_status,
                        callback_kwargs={"channel": request.channel}
                    )
                )

        if conf.ENABLE_CHANNEL_AUTH:
            if request.peer_target not in ObjectManager().rs_service.admin_manager.get_peer_list_by_channel(
                    request.channel):
                status, reason = message_code.get_response(message_code.Response.fail_invalid_peer_target)
                return loopchain_pb2.ConnectPeerReply(
                    status=status,
                    peer_list=b'',
                    more_info=reason
                )

        channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL if not request.channel else request.channel
        logging.debug(f"ConnectPeer channel_name({channel_name})")
        logging.debug(f"Connect Peer "
                      f"\nPeer_id : {request.peer_id}"
                      f"\nPeer_target : {request.peer_target}"
                      f"\nChannel : {request.channel}")

        peer = PeerInfo(request.peer_id, request.group_id, request.peer_target, PeerStatus.unknown)

        util.logger.spam(f"service::ConnectPeer try add_peer")

        # when first peer ConnectPeer to RS,
        # RS need rebuild peer list from db.
        # For prevent leader split by RS.
        with self.__load_peer_manager_lock:
            peer_manager = ObjectManager().rs_service.channel_manager. \
                get_peer_manager(channel_name)
            util.logger.spam(f"before load peer_manager "
                             f"peer_count({peer_manager.get_peer_count()})")

            if peer_manager.get_peer_count() == 0:
                util.logger.spam(f"try load peer_manager from db")
                # peer_manager = ObjectManager().rs_service.admin_manager.\
                #    load_peer_manager(channel_name)
                ObjectManager().rs_service.channel_manager. \
                    set_peer_manager(channel_name, peer_manager)

            util.logger.spam(f"after load peer_manager "
                             f"peer_count({peer_manager.get_peer_count()})")

            peer_order = peer_manager.add_peer(peer)

            peer_list_dumped = b''
            status, reason = message_code.get_response(message_code.Response.fail)

        if peer_order > 0:
            peer_list_dumped = peer_manager.peer_list_data.dump()
            status, reason = message_code.get_response(message_code.Response.success)

        # save current peer_manager after ConnectPeer from new peer.
        # ObjectManager().rs_service.admin_manager.save_peer_manager(channel_name, peer_manager)

        return loopchain_pb2.ConnectPeerReply(
            status=status,
            peer_list=peer_list_dumped,
            channels=None,
            more_info=reason
        )

    def GetPeerList(self, request, context):
        """현재 RadioStation 에 접속된 Peer 목록을 구한다.

        :param request: CommonRequest
        :param context:
        :return: PeerList
        """
        channel_manager = ObjectManager().rs_service.channel_manager
        channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL if not request.channel else request.channel

        if channel_name in channel_manager.get_channel_list():
            peer_manager: PeerManager = channel_manager.get_peer_manager(channel_name)
            peer_list_dumped = peer_manager.peer_list_data.dump()
        else:
            peer_list_dumped = PeerListData().dump()

        return loopchain_pb2.PeerList(
            peer_list=peer_list_dumped
        )

    def GetPeerStatus(self, request, context):
        # request parsing
        channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL if not request.channel else request.channel
        logging.debug(f"rs service GetPeerStatus peer_id({request.peer_id}) group_id({request.group_id})")

        # get stub of target peer
        peer_manager = ObjectManager().rs_service.channel_manager.get_peer_manager(channel_name)
        peer = peer_manager.get_peer(request.peer_id)
        if peer is not None:
            peer_stub_manager = peer_manager.get_peer_stub_manager(peer)
            if peer_stub_manager is not None:
                try:
                    response = peer_stub_manager.call_in_times(
                        "GetStatus",
                        loopchain_pb2.StatusRequest(request="get peer status from rs", channel=channel_name))
                    if response is not None:
                        return response
                except Exception as e:
                    logging.warning(f"fail GetStatus... ({e})")

        return loopchain_pb2.StatusReply(status="", block_height=0, total_tx=0)

    def AnnounceNewLeader(self, request, context):
        channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL if request.channel == '' else request.channel

        new_leader_peer = ObjectManager().rs_service.channel_manager.get_peer_manager(
            channel_name).get_peer(request.new_leader_id)

        if new_leader_peer is None:
            logging.warning(f"RadioStation Has No live Peer Connection(candidate reason is RS's restart)")
            logging.warning(f"RadioStation Request to Peers make Re-Connection")

            return loopchain_pb2.CommonReply(response_code=message_code.Response.fail_no_peer_info_in_rs,
                                             message=message_code.get_response_msg(
                                                 message_code.Response.fail_no_peer_info_in_rs))
        else:
            logging.debug(f"AnnounceNewLeader({channel_name}) "
                          f"id({request.new_leader_id}) "
                          f"target({new_leader_peer.target}): " + request.message)

            ObjectManager().rs_service.channel_manager.get_peer_manager(
                channel_name).set_leader_peer(peer=new_leader_peer)

            return loopchain_pb2.CommonReply(response_code=message_code.Response.success, message="success")

    def GetRandomTable(self, request, context):
        if conf.KEY_LOAD_TYPE == KeyLoadType.RANDOM_TABLE_DERIVATION:
            try:
                serialized_table = json.dumps(ObjectManager().rs_service.random_table)
                return loopchain_pb2.CommonReply(response_code=message_code.Response.success, message=serialized_table)
            except Exception as e:
                logging.error(f"random table serialize fail \n"
                              f"cause {e}")
                return loopchain_pb2.CommonReply(response_code=message_code.Response.fail,
                                                 messsage="random_table serialize fail")
        else:
            return loopchain_pb2.CommonReply(response_code=message_code.Response.fail,
                                             messsage="RadioStation KMS Policy is not enable")

    def Subscribe(self, request, context):
        """RadioStation 이 broadcast 하는 채널에 Peer 를 등록한다.

        :param request: SubscribeRequest
        :param context:
        :return: CommonReply
        """
        channel = conf.LOOPCHAIN_DEFAULT_CHANNEL if request.channel == '' else request.channel
        logging.debug("Radio Station Subscription peer_id: " + str(request))
        ObjectManager().rs_service.channel_manager.add_audience(channel, request.peer_target)

        peer: PeerInfo = ObjectManager().rs_service.channel_manager.get_peer_manager(channel).update_peer_status(
            peer_id=request.peer_id, peer_status=PeerStatus.connected)

        try:
            peer_dumped = peer.dump()
            request.peer_order = peer.order
            request.peer_object = peer_dumped

            return loopchain_pb2.CommonReply(
                response_code=message_code.get_response_code(message_code.Response.success),
                message=message_code.get_response_msg(message_code.Response.success))

        except Exception as e:
            logging.warning("Fail Peer Dump: " + str(e))
            return loopchain_pb2.CommonReply(response_code=message_code.get_response_code(message_code.Response.fail),
                                             message=message_code.get_response_msg(message_code.Response.fail))

    def UnSubscribe(self, request, context):
        """RadioStation 의 broadcast 채널에서 Peer 를 제외한다.

        :param request: SubscribeRequest
        :param context:
        :return: CommonReply
        """
        channel = conf.LOOPCHAIN_DEFAULT_CHANNEL if request.channel == '' else request.channel
        logging.debug("Radio Station UnSubscription peer_id: " + request.peer_target)
        channel_manager = ObjectManager().rs_service.channel_manager

        return loopchain_pb2.CommonReply(response_code=0, message="success")
