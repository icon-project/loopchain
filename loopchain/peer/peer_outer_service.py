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
"""gRPC service for Peer Outer Service"""

import asyncio
import copy
import datetime
from functools import partial

from loopchain.baseservice import TimerService
from loopchain.blockchain import *
from loopchain.peer import status_code
from loopchain.protos import loopchain_pb2_grpc, message_code, ComplainLeaderRequest, loopchain_pb2
from loopchain.utils.message_queue import StubCollection


class PeerOuterService(loopchain_pb2_grpc.PeerServiceServicer):
    """secure gRPC service for outer Client or other Peer
    """

    def __init__(self):
        self.__handler_map = {
            message_code.Request.status: self.__handler_status,
            message_code.Request.get_tx_result: self.__handler_get_tx_result,
            message_code.Request.get_balance: self.__handler_get_balance,
            message_code.Request.get_tx_by_address: self.__handler_get_tx_by_address,
            message_code.Request.get_total_supply: self.__handler_get_total_supply,
            message_code.Request.peer_peer_list: self.__handler_peer_list,
            message_code.Request.peer_reconnect_to_rs: self.__handler_reconnect_to_rs,
            message_code.Request.peer_restart_channel: self.__handler_restart_channel
        }

        self.__status_cache_update_time = {}

    @property
    def peer_service(self):
        return ObjectManager().peer_service

    def __handler_status(self, request, context):
        util.logger.debug(f"peer_outer_service:handler_status ({request.message})")

        if request.message == "get_stub_manager_to_server":
            # this case is check only gRPC available
            return loopchain_pb2.Message(code=message_code.Response.success)

        channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL if request.channel == '' else request.channel
        channel_stub = StubCollection().channel_stubs[channel_name]

        # FIXME : is need?
        if conf.ENABLE_REP_RADIO_STATION and request.message == "check peer status by rs":
            channel_stub.sync_task().reset_timer(TimerService.TIMER_KEY_CONNECT_PEER)

        callback = partial(self.__status_update, request.channel)
        future = asyncio.run_coroutine_threadsafe(
            channel_stub.async_task().get_status(),
            self.peer_service.inner_service.loop
        )
        future.add_done_callback(callback)

        status = self.__get_status_peer_type_data(request.channel)
        if status is None:
            return loopchain_pb2.Message(code=message_code.Response.fail)

        meta = json.loads(request.meta) if request.meta else {}
        if meta.get("highest_block_height", None) and meta["highest_block_height"] > status["block_height"]:
            util.logger.spam(f"(peer_outer_service.py:__handler_status) there is difference of height !")

        status_json = json.dumps(status)

        return loopchain_pb2.Message(code=message_code.Response.success, meta=status_json)

    def __handler_peer_list(self, request, context):
        channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL if request.channel == '' else request.channel

        channel_stub = StubCollection().channel_stubs[channel_name]
        all_group_peer_list_str, peer_list_str = channel_stub.sync_task().get_peer_list()

        message = "All Group Peers count: " + all_group_peer_list_str

        return loopchain_pb2.Message(
            code=message_code.Response.success,
            message=message,
            meta=peer_list_str)

    def __handler_get_tx_result(self, request, context):
        """Get Transaction Result for json-rpc request

        :param request:
        :param context:
        :return:
        """
        util.logger.spam(f"checking for test, code: {request.code}")
        util.logger.spam(f"checking for test, channel name: {request.channel}")
        util.logger.spam(f"checking for test, message: {request.message}")
        util.logger.spam(f"checking for test, meta: {json.loads(request.meta)}")

        params = json.loads(request.meta)

        util.logger.spam(f"params tx_hash({params['tx_hash']})")

        return loopchain_pb2.Message(code=message_code.Response.success)

    def __handler_get_balance(self, request, context):
        """Get Balance Tx for json-rpc request

        :param request:
        :param context:
        :return:
        """
        params = json.loads(request.meta)
        if 'address' not in params.keys():
            return loopchain_pb2.Message(code=message_code.Response.fail_illegal_params)

        query_request = loopchain_pb2.QueryRequest(params=request.meta, channel=request.channel)
        response = self.Query(query_request, context)
        util.logger.spam(f"peer_outer_service:__handler_get_balance response({response})")

        return loopchain_pb2.Message(code=response.response_code, meta=response.response)

    def __handler_get_total_supply(self, request, context):
        """Get Total Supply

        :param request:
        :param context:
        :return:
        """
        query_request = loopchain_pb2.QueryRequest(params=request.meta, channel=request.channel)
        response = self.Query(query_request, context)
        util.logger.spam(f"peer_outer_service:__handler_get_total_supply response({response})")

        return loopchain_pb2.Message(code=response.response_code, meta=response.response)

    def __handler_get_tx_by_address(self, request, context):
        """Get Transaction by address

        :param request:
        :param context:
        :return:
        """
        params = json.loads(request.meta)
        address = params.pop('address', None)
        index = params.pop('index', None)

        if address is None or index is None:  # or params:
            return loopchain_pb2.Message(code=message_code.Response.fail_illegal_params)

        channel_stub = StubCollection().channel_stubs[request.channel]
        tx_list, next_index = channel_stub.sync_task().get_tx_by_address(address, index)

        tx_list_dumped = json.dumps(tx_list).encode(encoding=conf.PEER_DATA_ENCODING)
        return loopchain_pb2.Message(code=message_code.Response.success,
                                     meta=str(next_index),
                                     object=tx_list_dumped)

    def __handler_reconnect_to_rs(self, request, context):
        logging.warning(f"RS lost peer info (candidate reason: RS restart)")
        logging.warning(f"try reconnect to RS....")
        ObjectManager().channel_service.connect_to_radio_station(is_reconnect=True)

        return loopchain_pb2.Message(code=message_code.Response.success)

    def __handler_restart_channel(self, request, context):
        logging.debug(f"Restart_channel({request.channel}) code({request.code}), message({request.message})")

        ObjectManager().peer_service.start_channel(
            channel=request.channel,
            is_restart=True
        )

        return loopchain_pb2.Message(code=message_code.Response.success)

    def Request(self, request, context):
        # util.logger.debug(f"Peer Service got request({request.code})")

        if request.code in self.__handler_map.keys():
            return self.__handler_map[request.code](request, context)

        return loopchain_pb2.Message(code=message_code.Response.not_treat_message_code)

    def __status_update(self, channel, future):
        # update peer outer status cache by channel
        util.logger.spam(f"status_update channel({channel}) result({future.result()})")
        self.__status_cache_update_time[channel] = datetime.datetime.now()
        self.peer_service.status_cache[channel] = future.result()

    def __get_status_data(self, channel: str):
        return self.__get_status_from_cache(channel)

    def __get_status_peer_type_data(self, channel: str):
        status_cache = self.__get_status_from_cache(channel)
        status = dict()
        status['state'] = status_cache['state']
        status['peer_type'] = status_cache['peer_type']
        status['block_height'] = status_cache['block_height']
        status['peer_count'] = status_cache['peer_count']
        status['leader'] = status_cache['leader']
        return status

    def __get_status_from_cache(self, channel: str):
        if channel in self.peer_service.status_cache:
            if channel in self.__status_cache_update_time:
                if util.datetime_diff_in_mins(
                        self.__status_cache_update_time[channel]) \
                        > conf.ALLOW_STATUS_CACHE_LAST_UPDATE_IN_MINUTES:
                    return None
            status_data = self.peer_service.status_cache[channel]
        else:
            channel_stub = StubCollection().channel_stubs[channel]
            status_data = channel_stub.sync_task().get_status()
            self.peer_service.status_cache[channel] = status_data

        return status_data

    def GetStatus(self, request, context):
        """Peer 의 현재 상태를 요청한다.

        :param request:
        :param context:
        :return:
        """
        channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL if request.channel == '' else request.channel
        logging.debug("Peer GetStatus : %s", request)

        try:
            channel_stub = StubCollection().channel_stubs[channel_name]

            callback = partial(self.__status_update, channel_name)
            future = asyncio.run_coroutine_threadsafe(
                channel_stub.async_task().get_status(),
                self.peer_service.inner_service.loop)
            future.add_done_callback(callback)

        except BaseException as e:
            logging.error(f"Peer GetStatus Exception : {e}")

        status_data = self.__get_status_data(channel_name)
        if status_data is None:
            raise ChannelStatusError(f"Fail get status data from channel({channel_name})")

        status_data = copy.deepcopy(status_data)

        stubs = {
            "peer": StubCollection().peer_stub,
            "channel": StubCollection().channel_stubs.get(channel_name),
            "score": StubCollection().icon_score_stubs.get(channel_name)
        }

        mq_status_data = {}
        mq_down = False
        for key, stub in stubs.items():
            message_count = -1
            message_error = None
            try:
                mq_info = stub.sync_info().queue_info()
                message_count = mq_info.method.message_count
            except AttributeError:
                message_error = "Stub is not initialized."
            except Exception as e:
                message_error = f"{type(e).__name__}, {e}"

            mq_status_data[key] = {}
            mq_status_data[key]["message_count"] = message_count
            if message_error:
                mq_status_data[key]["error"] = message_error
                mq_down = True

        status_data["mq"] = mq_status_data
        if mq_down:
            reason = status_code.get_status_reason(status_code.Service.mq_down)
            status_data["status"] = "Service is offline: " + reason

        return loopchain_pb2.StatusReply(
            status=json.dumps(status_data),
            block_height=status_data["block_height"],
            total_tx=status_data["total_tx"],
            unconfirmed_block_height=status_data["unconfirmed_block_height"],
            is_leader_complaining=status_data['leader_complaint'],
            peer_id=status_data['peer_id'])

    def GetScoreStatus(self, request, context):
        """Score Service 의 현재 상태를 요청 한다

        :param request:
        :param context:
        :return:
        """
        logging.debug("Peer GetScoreStatus request : %s", request)

        channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL if request.channel == '' else request.channel
        channel_stub = StubCollection().channel_stubs[channel_name]
        score_status = channel_stub.sync_task().get_score_status()

        return loopchain_pb2.StatusReply(
            status=score_status,
            block_height=0,
            total_tx=0)

    def Stop(self, request, context):
        """Peer를 중지시킨다

        :param request: 중지요청
        :param context:
        :return: 중지결과
        """
        if request is not None:
            logging.info('Peer will stop... by: ' + request.reason)

        try:
            for channel_name in self.peer_service.channel_infos:
                channel_stub = StubCollection().channel_stubs[channel_name]
                channel_stub.sync_task().stop()

            self.peer_service.p2p_server_stop()

        except Exception as e:
            logging.debug("Score Service Already stop by other reason. %s", e)

        return loopchain_pb2.StopReply(status="0")

    def Echo(self, request, context):
        """gRPC 기본 성능을 확인하기 위한 echo interface, loopchain 기능과는 무관하다.

        :return: request 를 message 되돌려 준다.
        """
        return loopchain_pb2.CommonReply(response_code=message_code.Response.success,
                                         message=request.request)

    def ComplainLeader(self, request: ComplainLeaderRequest, context):
        channel = conf.LOOPCHAIN_DEFAULT_CHANNEL if request.channel == '' else request.channel
        util.logger.notice(f"ComplainLeader "
                           f"height({request.block_height}) complained_peer({request.complained_leader_id})")

        channel_stub = StubCollection().channel_stubs[channel]
        channel_stub.sync_task().complain_leader(
            complained_leader_id=request.complained_leader_id,
            new_leader_id=request.new_leader_id,
            block_height=request.block_height,
            peer_id=request.peer_id,
            group_id=request.group_id
        )

        return loopchain_pb2.CommonReply(response_code=message_code.Response.success, message="success")

    def CreateTx(self, request, context):
        """make tx by client request and broadcast it to the network

        :param request:
        :param context:
        :return:
        """
        channel_name = request.channel or conf.LOOPCHAIN_DEFAULT_CHANNEL
        logging.info(f"peer_outer_service::CreateTx request({request.data}), channel({channel_name})")

        channel_stub = StubCollection().channel_stubs[channel_name]
        result_hash = channel_stub.sync_task().create_tx(request.data)

        return loopchain_pb2.CreateTxReply(
            response_code=message_code.Response.success,
            tx_hash=result_hash,
            more_info='')

    def AddTx(self, request: loopchain_pb2.TxSend, context):
        """Add tx to Block Manager

        :param request:
        :param context:
        :return:
        """

        util.logger.spam(f"peer_outer_service:AddTx try validate_dumped_tx_message")
        channel_name = request.channel or conf.LOOPCHAIN_DEFAULT_CHANNEL
        StubCollection().channel_stubs[channel_name].sync_task().add_tx(request)
        return loopchain_pb2.CommonReply(response_code=message_code.Response.success, message="success")

    def AddTxList(self, request: loopchain_pb2.TxSendList, context):
        """Add tx to Block Manager

        :param request:
        :param context:
        :return:
        """
        util.logger.spam(f"peer_outer_service:AddTxList try validate_dumped_tx_message")
        channel_name = request.channel or conf.LOOPCHAIN_DEFAULT_CHANNEL
        StubCollection().channel_tx_receiver_stubs[channel_name].sync_task().add_tx_list(request)
        return loopchain_pb2.CommonReply(response_code=message_code.Response.success, message="success")

    def GetTx(self, request, context):
        """get transaction

        :param request: tx_hash
        :param context:channel_loopchain_default
        :return:
        """
        channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL if request.channel == '' else request.channel

        channel_stub = StubCollection().channel_stubs[channel_name]
        tx = channel_stub.sync_task().get_tx(request.tx_hash)

        response_code, response_msg = message_code.get_response(message_code.Response.fail)
        response_meta = ""
        response_data = ""
        response_sign = b''
        response_public_key = b''

        if tx is not None:
            response_code, response_msg = message_code.get_response(message_code.Response.success)
            response_meta = json.dumps(tx.meta)
            response_data = tx.get_data().decode(conf.PEER_DATA_ENCODING)
            response_sign = tx.signature
            response_public_key = tx.public_key

        return loopchain_pb2.GetTxReply(response_code=response_code,
                                        meta=response_meta,
                                        data=response_data,
                                        signature=response_sign,
                                        public_key=response_public_key,
                                        more_info=response_msg)

    def GetLastBlockHash(self, request, context):
        """ 마지막 블럭 조회

        :param request: 블럭요청
        :param context:
        :return: 마지막 블럭
        """
        channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL if request.channel == '' else request.channel
        # Peer To Client
        channel_stub = StubCollection().channel_stubs[channel_name]
        response_code, block_hash, _, block_data_json, tx_data_json_list = \
            channel_stub.sync_task().get_block(
                block_height=-1,
                block_hash='',
                block_data_filter='block_hash',
                tx_data_filter='')

        response_code, response_msg = message_code.get_response(response_code)
        return loopchain_pb2.BlockReply(response_code=response_code,
                                        message=response_msg,
                                        block_hash=block_hash)

    def GetBlock(self, request, context):
        """Block 정보를 조회한다.

        :param request: loopchain.proto 의 GetBlockRequest 참고
         request.block_hash: 조회할 block 의 hash 값, "" 로 조회하면 마지막 block 의 hash 값을 리턴한다.
         request.block_data_filter: block 정보 중 조회하고 싶은 key 값 목록 "key1, key2, key3" 형식의 string
         request.tx_data_filter: block 에 포함된 transaction(tx) 중 조회하고 싶은 key 값 목록
        "key1, key2, key3" 형식의 string
        :param context:
        :return: loopchain.proto 의 GetBlockReply 참고,
        block_hash, block 정보 json, block 에 포함된 tx 정보의 json 리스트를 받는다.
        포함되는 정보는 param 의 filter 에 따른다.
        """

        channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL if request.channel == '' else request.channel

        channel_stub = StubCollection().channel_stubs[channel_name]
        response_code, block_hash, confirm_info, block_data_json, tx_data_json_list = \
            channel_stub.sync_task().get_block(
                block_height=request.block_height,
                block_hash=request.block_hash,
                block_data_filter=request.block_data_filter,
                tx_data_filter=request.tx_data_filter)

        return loopchain_pb2.GetBlockReply(response_code=response_code,
                                           block_hash=block_hash,
                                           block_data_json=block_data_json,
                                           confirm_info=confirm_info,
                                           tx_data_json=tx_data_json_list)

    def GetPrecommitBlock(self, request, context):
        """Return the precommit bock.

        :param request:
        :param context:
        :return: loopchain.proto 의 PrecommitBlockReply 참고,
        """

        channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL if request.channel == '' else request.channel
        channel_stub = StubCollection().channel_stubs[channel_name]
        response_code, response_message, block = \
            channel_stub.sync_task().get_precommit_block(last_block_height=request.last_block_height)

        return loopchain_pb2.PrecommitBlockReply(
            response_code=response_code, response_message=response_message, block=block)

    def Query(self, request, context):
        """Score 의 invoke 로 생성된 data 에 대한 query 를 수행한다."""
        channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL if request.channel == '' else request.channel

        score_stub = StubCollection().score_stubs[channel_name]
        response_code, response = score_stub.sync_task().query(request.params)

        return loopchain_pb2.QueryReply(response_code=response_code, response=response)

    def GetInvokeResult(self, request, context):
        """get invoke result by tx_hash

        :param request: request.tx_hash = tx_hash
        :param context:
        :return: verify result
        """
        channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL if request.channel == '' else request.channel
        logging.debug(f"peer_outer_service:GetInvokeResult in channel({channel_name})")

        channel_stub = StubCollection().channel_stubs[channel_name]
        response_code, result = channel_stub.sync_task().get_invoke_result(request.tx_hash)
        return loopchain_pb2.GetInvokeResultReply(response_code=response_code, result=result)

    def AnnounceUnconfirmedBlock(self, request, context):
        """수집된 tx 로 생성한 Block 을 각 peer 에 전송하여 검증을 요청한다.

        :param request:
        :param context:
        :return:
        """
        channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL if request.channel == '' else request.channel
        util.logger.debug(f"peer_outer_service::AnnounceUnconfirmedBlock channel({channel_name})")

        channel_stub = StubCollection().channel_stubs[channel_name]
        channel_stub.sync_task().announce_unconfirmed_block(request.block)
        return loopchain_pb2.CommonReply(response_code=message_code.Response.success, message="success")

    def BlockSync(self, request, context):
        # Peer To Peer
        channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL if request.channel == '' else request.channel
        logging.info(f"BlockSync request hash({request.block_hash}) "
                     f"request height({request.block_height}) channel({channel_name})")

        channel_stub = StubCollection().channel_stubs[channel_name]
        response_code, block_height, max_block_height, unconfirmed_block_height, confirm_info, block_dumped = \
            channel_stub.sync_task().block_sync(request.block_hash, request.block_height)

        return loopchain_pb2.BlockSyncReply(
            response_code=response_code,
            block_height=block_height,
            max_block_height=max_block_height,
            confirm_info=bytes(confirm_info) if confirm_info else b"",
            block=block_dumped,
            unconfirmed_block_height=unconfirmed_block_height)

    def Subscribe(self, request, context):
        """BlockGenerator 가 broadcast(unconfirmed or confirmed block) 하는 채널에
        Peer 를 등록한다.

        :param request:
        :param context:
        :return:
        """
        channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL if request.channel == '' else request.channel
        if not request.peer_id or not request.peer_target:
            return loopchain_pb2.CommonReply(
                response_code=message_code.get_response_code(message_code.Response.fail_wrong_subscribe_info),
                message=message_code.get_response_msg(message_code.Response.fail_wrong_subscribe_info)
            )

        try:
            channel_stub = StubCollection().channel_stubs[channel_name]
        except KeyError:
            return loopchain_pb2.CommonReply(response_code=message_code.get_response_code(message_code.Response.fail),
                                             message=f"There is no channel_stubs for channel({channel_name}).")

        peer_list = [target['peer_target'] for target in self.peer_service.channel_infos[channel_name]["peers"]]

        if (request.peer_target in peer_list and conf.ENABLE_CHANNEL_AUTH) or \
                (request.node_type == loopchain_pb2.CommunityNode and not conf.ENABLE_CHANNEL_AUTH):
            channel_stub.sync_task().add_audience(peer_target=request.peer_target)
            util.logger.debug(f"peer_outer_service::Subscribe add_audience "
                              f"target({request.peer_target}) in channel({request.channel}), "
                              f"order({request.peer_order})")
        else:
            logging.error(f"This target({request.peer_target}, {request.node_type}) failed to subscribe.")
            return loopchain_pb2.CommonReply(response_code=message_code.get_response_code(message_code.Response.fail),
                                             message=message_code.get_response_msg("Unknown type peer"))

        return loopchain_pb2.CommonReply(response_code=message_code.get_response_code(message_code.Response.success),
                                         message=message_code.get_response_msg(message_code.Response.success))

    def UnSubscribe(self, request, context):
        """BlockGenerator 의 broadcast 채널에서 Peer 를 제외한다.

        :param request:
        :param context:
        :return:
        """
        channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL if request.channel == '' else request.channel

        channel_stub = StubCollection().channel_stubs[channel_name]
        peer_list = [target['peer_target'] for target in self.peer_service.channel_infos[channel_name]["peers"]]

        if (request.peer_target in peer_list and conf.ENABLE_CHANNEL_AUTH) or \
                (request.node_type == loopchain_pb2.CommunityNode and not conf.ENABLE_CHANNEL_AUTH):
            channel_stub.sync_task().remove_audience(peer_target=request.peer_target)
            util.logger.spam(f"peer_outer_service::Unsubscribe remove_audience target({request.peer_target}) "
                             f"in channel({request.channel})")
        else:
            logging.error(f"This target({request.peer_target}), {request.node_type} failed to unsubscribe.")
            return loopchain_pb2.CommonReply(response_code=message_code.get_response_code(message_code.Response.fail),
                                             message=message_code.get_response_msg("Unknown type peer"))

        return loopchain_pb2.CommonReply(response_code=message_code.get_response_code(message_code.Response.success),
                                         message=message_code.get_response_msg(message_code.Response.success))

    def AnnounceNewPeer(self, request, context):
        """RadioStation에서 Broadcasting 으로 신규 피어정보를 받아온다

        :param request: PeerRequest
        :param context:
        :return:
        """
        # RadioStation To Peer
        # prevent to show certificate content
        # logging.info('Here Comes new peer: ' + str(request))
        channel = conf.LOOPCHAIN_DEFAULT_CHANNEL if request.channel == '' else request.channel
        logging.debug(f"peer outer service::AnnounceNewPeer channel({channel})")

        if request.peer_object:
            channel_stub = StubCollection().channel_stubs[channel]
            channel_stub.sync_task().announce_new_peer(request.peer_object, request.peer_target)

        return loopchain_pb2.CommonReply(response_code=0, message="success")

    def AnnounceDeletePeer(self, request, context):
        """delete peer by radio station heartbeat, It delete peer info over whole channels.

        :param request:
        :param context:
        :return:
        """
        channel = conf.LOOPCHAIN_DEFAULT_CHANNEL if request.channel == '' else request.channel
        logging.debug(f"AnnounceDeletePeer peer_id({request.peer_id}) group_id({request.group_id})")

        if self.peer_service.peer_id != request.peer_id:
            channel_stub = StubCollection().channel_stubs[channel]
            channel_stub.sync_task().delete_peer(request.peer_id, request.group_id)

        return loopchain_pb2.CommonReply(response_code=0, message="success")

    def VoteUnconfirmedBlock(self, request, context):
        channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL if request.channel == '' else request.channel

        util.logger.debug(f"VoteUnconfirmedBlock block_hash({request.block_hash})")

        channel_stub = StubCollection().channel_stubs[channel_name]
        channel_stub.sync_task().vote_unconfirmed_block(
            peer_id=request.peer_id,
            group_id=request.group_id,
            block_hash=request.block_hash,
            vote_code=request.vote_code)

        return loopchain_pb2.CommonReply(response_code=message_code.Response.success, message="success")

    def AnnounceNewLeader(self, request, context):
        if not request.channel:
            raise Exception("peer_outer_service:AnnounceNewLeader : Channel is not defined.")

        logging.debug(f"AnnounceNewLeader({request.channel}): " + request.message)

        channel_stub = StubCollection().channel_stubs[request.channel]
        channel_stub.sync_task().reset_leader(request.new_leader_id)

        return loopchain_pb2.CommonReply(response_code=message_code.Response.success, message="success")

    def GetChannelInfos(self, request: loopchain_pb2.GetChannelInfosRequest, context):
        """Return channels by peer target

        :param request:
        :param context:
        :return:
        """
        logging.info(f"peer_outer_service:GetChannelInfos target({request.peer_target}) "
                     f"channel_infos({ObjectManager().peer_service.channel_infos})")

        return loopchain_pb2.GetChannelInfosReply(
            response_code=message_code.Response.success,
            channel_infos=json.dumps(ObjectManager().peer_service.channel_infos)
        )
