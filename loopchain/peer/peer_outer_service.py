"""gRPC service for Peer Outer Service"""

import asyncio
import copy
import json
import typing

import math
import time

from loopchain import configure as conf
from loopchain import utils
from loopchain.baseservice.lru_cache import lru_cache
from loopchain.blockchain import ChannelStatusError
from loopchain.peer import status_code
from loopchain.protos import loopchain_pb2_grpc, message_code, ComplainLeaderRequest, loopchain_pb2
from loopchain.utils.message_queue import StubCollection

if typing.TYPE_CHECKING:
    from loopchain.peer import PeerService


class PeerOuterService(loopchain_pb2_grpc.PeerServiceServicer):
    """secure gRPC service for outer Client or other Peer
    """

    def __init__(self, peer_service: 'PeerService'):
        self.__status_cache = None
        self._peer_service = peer_service

    @property
    def peer_service(self) -> 'PeerService':
        return self._peer_service

    def __set_status_cache(self, future):
        self.__status_cache = future.result()

    @lru_cache(maxsize=1, valued_returns_only=True)
    def __get_status_cache(self, channel_name, time_in_seconds):
        """Cache status data.

        :param channel_name:
        :param time_in_seconds: An essential parameter for the `LRU cache` even if not used.

        :return:
        """
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

    async def GetStatus(self, request, context):
        """Request current status of Peer
        TODO: GetStatus is deprecated, it should be removed after version 2.7.0

        :param request:
        :param context:
        :return:
        """
        channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL if request.channel == '' else request.channel

        try:
            channel_stub = StubCollection().channel_stubs[channel_name]
        except KeyError:
            raise ChannelStatusError(f"Invalid channel({channel_name})")

        status_data: typing.Optional[dict] = None
        if request.request == 'block_sync':
            try:
                status_data = typing.cast(dict, channel_stub.sync_task().get_status())
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

    async def ComplainLeader(self, request: ComplainLeaderRequest, context):
        channel = conf.LOOPCHAIN_DEFAULT_CHANNEL if request.channel == '' else request.channel
        utils.logger.info(f"complain_vote: {request.complain_vote}")

        channel_stub = StubCollection().channel_stubs[channel]
        await channel_stub.async_task().complain_leader(vote_dumped=request.complain_vote)

        return loopchain_pb2.CommonReply(response_code=message_code.Response.success, message="success")

    async def AddTxList(self, request: loopchain_pb2.TxSendList, context):
        """Add tx to Block Manager

        :param request:
        :param context:
        :return:
        """
        utils.logger.info(f"length of txlist: {len(request.tx_list)}")
        channel_name = request.channel or conf.LOOPCHAIN_DEFAULT_CHANNEL
        tx_receiver_stub = StubCollection().channel_tx_receiver_stubs[channel_name]
        await tx_receiver_stub.async_task().add_tx_list(request)
        return loopchain_pb2.CommonReply(response_code=message_code.Response.success, message="success")

    async def AnnounceUnconfirmedBlock(self, request, context):
        """Send the UnconfirmedBlock includes collected transactions to reps and request to verify it.

        :param request:
        :param context:
        :return:
        """
        channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL if request.channel == '' else request.channel
        channel_stub = StubCollection().channel_stubs[channel_name]

        try:
            round_ = request.round_
        except AttributeError:
            round_ = 0

        utils.logger.info(f"peer_id({request.peer_id}), height({request.height}), "
                          f"round({round_}), hash({request.hash}, from_recovery({request.from_recovery!r})")

        from_recovery = request.from_recovery if request.from_recovery else False

        await channel_stub.async_task().announce_unconfirmed_block(request.block, round_, from_recovery)
        return loopchain_pb2.CommonReply(response_code=message_code.Response.success, message="success")

    async def BlockSync(self, request, context):
        # Peer To Peer
        channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL if request.channel == '' else request.channel

        utils.logger.info(
            f"request height({request.block_height}) channel({channel_name})")

        channel_stub = StubCollection().channel_stubs[channel_name]
        response_code, block_height, max_block_height, unconfirmed_block_height, confirm_info, block_dumped = (
            await channel_stub.async_task().block_sync(request.block_height)
        )

        return loopchain_pb2.BlockSyncReply(
            response_code=response_code,
            block_height=block_height,
            max_block_height=max_block_height,
            confirm_info=confirm_info,
            block=block_dumped,
            unconfirmed_block_height=unconfirmed_block_height)

    async def VoteUnconfirmedBlock(self, request, context):
        channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL if request.channel == '' else request.channel

        utils.logger.info(f"vote({request.vote})")

        channel_stub = StubCollection().channel_stubs[channel_name]
        await channel_stub.async_task().vote_unconfirmed_block(request.vote)
        return loopchain_pb2.CommonReply(response_code=message_code.Response.success, message="success")
