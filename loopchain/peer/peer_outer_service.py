"""gRPC service for Peer Outer Service"""

import asyncio
import copy
import json
import logging
import math
import time

from loopchain import configure as conf
from loopchain import utils
from loopchain.baseservice import ObjectManager
from loopchain.baseservice.lru_cache import lru_cache
from loopchain.blockchain import ChannelStatusError
from loopchain.peer import status_code
from loopchain.protos import loopchain_pb2_grpc, message_code, ComplainLeaderRequest, loopchain_pb2
from loopchain.utils.message_queue import StubCollection


class PeerOuterService(loopchain_pb2_grpc.PeerServiceServicer):
    """secure gRPC service for outer Client or other Peer
    """

    def __init__(self):
        self.__handler_map = {
            message_code.Request.get_tx_result: self.__handler_get_tx_result,
            message_code.Request.get_balance: self.__handler_get_balance,
            message_code.Request.get_tx_by_address: self.__handler_get_tx_by_address,
            message_code.Request.get_total_supply: self.__handler_get_total_supply
        }

        self.__status_cache = None

    @property
    def peer_service(self):
        return ObjectManager().peer_service

    def __handler_get_tx_result(self, request, context):
        """Get Transaction Result for json-rpc request

        :param request:
        :param context:
        :return:
        """
        utils.logger.spam(f"checking for test, code: {request.code}")
        utils.logger.spam(f"checking for test, channel name: {request.channel}")
        utils.logger.spam(f"checking for test, message: {request.message}")
        utils.logger.spam(f"checking for test, meta: {json.loads(request.meta)}")

        params = json.loads(request.meta)

        utils.logger.spam(f"params tx_hash({params['tx_hash']})")

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
        utils.logger.spam(f"peer_outer_service:__handler_get_balance response({response})")

        return loopchain_pb2.Message(code=response.response_code, meta=response.response)

    def __handler_get_total_supply(self, request, context):
        """Get Total Supply

        :param request:
        :param context:
        :return:
        """
        query_request = loopchain_pb2.QueryRequest(params=request.meta, channel=request.channel)
        response = self.Query(query_request, context)
        utils.logger.spam(f"peer_outer_service:__handler_get_total_supply response({response})")

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
        future = asyncio.run_coroutine_threadsafe(
            channel_stub.async_task().get_tx_by_address(address, index),
            self.peer_service.inner_service.loop
        )
        tx_list, next_index = future.result()
        tx_list_dumped = json.dumps(tx_list).encode(encoding=conf.PEER_DATA_ENCODING)

        return loopchain_pb2.Message(code=message_code.Response.success,
                                     meta=str(next_index),
                                     object=tx_list_dumped)

    def Request(self, request, context):
        # utils.logger.debug(f"Peer Service got request({request.code})")

        if request.code in self.__handler_map.keys():
            return self.__handler_map[request.code](request, context)

        return loopchain_pb2.Message(code=message_code.Response.not_treat_message_code)

    def __set_status_cache(self, future):
        self.__status_cache = future.result()

    @lru_cache(maxsize=1, valued_returns_only=True)
    def __get_status_cache(self, channel_name, time_in_seconds):
        # utils.logger.spam(f"__get_status_cache in seconds({time_in_seconds})")
        try:
            channel_stub = StubCollection().channel_stubs[channel_name]
        except KeyError:
            raise ChannelStatusError(f"Invalid channel({channel_name})")

        if self.__status_cache is None:
            self.__status_cache = channel_stub.sync_task().get_status()
        else:
            future = asyncio.run_coroutine_threadsafe(
                channel_stub.async_task().get_status(),
                self.peer_service.inner_service.loop)
            future.add_done_callback(self.__set_status_cache)

        return self.__status_cache

    def GetStatus(self, request, context):
        """Peer 의 현재 상태를 요청한다.

        :param request:
        :param context:
        :return:
        """
        channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL if request.channel == '' else request.channel

        try:
            channel_stub = StubCollection().channel_stubs[channel_name]
        except KeyError:
            raise ChannelStatusError(f"Invalid channel({channel_name})")

        status_data = None
        if request.request == 'block_sync':
            try:
                status_data = channel_stub.sync_task().get_status()
                # utils.logger.debug(f"Got status for block_sync. status_data={status_data}")
            except BaseException as e:
                utils.logger.error(f"Peer GetStatus(block_sync) Exception : {e}")
        else:
            status_data = self.__get_status_cache(channel_name,
                                                  time_in_seconds=math.trunc(time.time()))

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

    def Stop(self, request, context):
        """Peer를 중지시킨다

        :param request: 중지요청
        :param context:
        :return: 중지결과
        """
        if request is not None:
            utils.logger.info('Peer will stop... by: ' + request.reason)

        try:
            for channel_name in conf.CHANNEL_OPTION:
                channel_stub = StubCollection().channel_stubs[channel_name]
                asyncio.run_coroutine_threadsafe(channel_stub.async_task().stop(), self.peer_service.inner_service.loop)

            self.peer_service.p2p_server_stop()

        except Exception as e:
            utils.logger.debug("Score Service Already stop by other reason. %s", e)

        return loopchain_pb2.StopReply(status="0")

    def Echo(self, request, context):
        """gRPC 기본 성능을 확인하기 위한 echo interface, loopchain 기능과는 무관하다.

        :return: request 를 message 되돌려 준다.
        """
        return loopchain_pb2.CommonReply(response_code=message_code.Response.success,
                                         message=request.request)

    def ComplainLeader(self, request: ComplainLeaderRequest, context):
        channel = conf.LOOPCHAIN_DEFAULT_CHANNEL if request.channel == '' else request.channel
        utils.logger.info(f"ComplainLeader {request.complain_vote}")

        channel_stub = StubCollection().channel_stubs[channel]
        asyncio.run_coroutine_threadsafe(
            channel_stub.async_task().complain_leader(vote_dumped=request.complain_vote),
            self.peer_service.inner_service.loop
        )

        return loopchain_pb2.CommonReply(response_code=message_code.Response.success, message="success")

    def CreateTx(self, request, context):
        """make tx by client request and broadcast it to the network

        :param request:
        :param context:
        :return:
        """
        channel_name = request.channel or conf.LOOPCHAIN_DEFAULT_CHANNEL
        utils.logger.info(f"peer_outer_service::CreateTx request({request.data}), channel({channel_name})")

        channel_stub = StubCollection().channel_stubs[channel_name]
        result_hash = asyncio.run_coroutine_threadsafe(
            channel_stub.async_task().create_tx(request.data),
            self.peer_service.inner_service.loop
        ).result()

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

        utils.logger.spam(f"peer_outer_service:AddTx try validate_dumped_tx_message")
        channel_name = request.channel or conf.LOOPCHAIN_DEFAULT_CHANNEL
        StubCollection().channel_stubs[channel_name].sync_task().add_tx(request)
        return loopchain_pb2.CommonReply(response_code=message_code.Response.success, message="success")

    def AddTxList(self, request: loopchain_pb2.TxSendList, context):
        """Add tx to Block Manager

        :param request:
        :param context:
        :return:
        """
        utils.logger.spam(f"peer_outer_service:AddTxList try validate_dumped_tx_message")
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
        tx = asyncio.run_coroutine_threadsafe(
            channel_stub.async_task().get_tx(request.tx_hash),
            self.peer_service.inner_service.loop
        ).result()

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

    def GetPrecommitBlock(self, request, context):
        """Return the precommit bock.

        :param request:
        :param context:
        :return: loopchain.proto 의 PrecommitBlockReply 참고,
        """

        channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL if request.channel == '' else request.channel
        channel_stub = StubCollection().channel_stubs[channel_name]
        future = asyncio.run_coroutine_threadsafe(
            channel_stub.async_task().get_precommit_block(last_block_height=request.last_block_height),
            self.peer_service.inner_service.loop
        )
        response_code, response_message, block = future.result()

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
        utils.logger.debug(f"peer_outer_service:GetInvokeResult in channel({channel_name})")

        channel_stub = StubCollection().channel_stubs[channel_name]
        future = asyncio.run_coroutine_threadsafe(
            channel_stub.async_task().get_invoke_result(request.tx_hash),
            self.peer_service.inner_service.loop
        )
        response_code, result = future.result()

        return loopchain_pb2.GetInvokeResultReply(response_code=response_code, result=result)

    def AnnounceUnconfirmedBlock(self, request, context):
        """Send the UnconfirmedBlock includes collected transactions to reps and request to verify it.

        :param request:
        :param context:
        :return:
        """
        channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL if request.channel == '' else request.channel
        channel_stub = StubCollection().channel_stubs[channel_name]

        try:
            round_ = request.round
        except AttributeError:
            round_ = 0

        asyncio.run_coroutine_threadsafe(
            channel_stub.async_task().announce_unconfirmed_block(request.block, round_),
            self.peer_service.inner_service.loop
        )
        return loopchain_pb2.CommonReply(response_code=message_code.Response.success, message="success")

    def BlockSync(self, request, context):
        # Peer To Peer
        channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL if request.channel == '' else request.channel
        utils.logger.info(
            f"BlockSync request hash({request.block_hash}) "
            f"request height({request.block_height}) channel({channel_name})")

        channel_stub = StubCollection().channel_stubs[channel_name]
        future = asyncio.run_coroutine_threadsafe(
            channel_stub.async_task().block_sync(request.block_hash, request.block_height),
            self.peer_service.inner_service.loop
        )
        response_code, block_height, max_block_height, unconfirmed_block_height, confirm_info, block_dumped = \
            future.result()

        return loopchain_pb2.BlockSyncReply(
            response_code=response_code,
            block_height=block_height,
            max_block_height=max_block_height,
            confirm_info=confirm_info,
            block=block_dumped,
            unconfirmed_block_height=unconfirmed_block_height)

    def VoteUnconfirmedBlock(self, request, context):
        channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL if request.channel == '' else request.channel

        utils.logger.debug(f"VoteUnconfirmedBlock vote({request.vote})")

        channel_stub = StubCollection().channel_stubs[channel_name]
        asyncio.run_coroutine_threadsafe(
            channel_stub.async_task().vote_unconfirmed_block(request.vote),
            self.peer_service.inner_service.loop
        )
        return loopchain_pb2.CommonReply(response_code=message_code.Response.success, message="success")
