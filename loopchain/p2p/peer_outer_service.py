"""gRPC service for Peer Outer Service"""

import asyncio
import copy
import json

from loopchain import utils, configure as conf
from loopchain.baseservice.lru_cache import lru_cache
from loopchain.p2p import message_code, status_code
from loopchain.p2p.bridge import PeerBridgeBase
from loopchain.p2p.protos import loopchain_pb2, loopchain_pb2_grpc, ComplainLeaderRequest
from loopchain.utils.message_queue import StubCollection


class PeerOuterService(loopchain_pb2_grpc.PeerServiceServicer):
    """secure gRPC service for outer Client or other Peer
    """

    def __init__(self, peer_bridge):
        self._peer_bridge: PeerBridgeBase = peer_bridge
        self.__status_cache = None

    @property
    def peer_service(self):
        # TODO : remove ObjectManager
        from loopchain.baseservice import ObjectManager
        return ObjectManager().peer_service

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
            # TODO : remove import from loopchain.blockchain
            from loopchain.blockchain import ChannelStatusError
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
        """Request current status of Peer

        :param request:
        :param context:
        :return:
        """
        channel_name = request.channel or conf.LOOPCHAIN_DEFAULT_CHANNEL

        status_data = self._peer_bridge.channel_get_status_data(channel_name, request.request)

        status_data = copy.deepcopy(status_data)

        mq_status_data = self._peer_bridge.channel_mq_status_data(channel_name)

        if True in map(lambda x: 'error' in x, mq_status_data.values()):
            reason = status_code.get_status_reason(status_code.Service.mq_down)
            status_data["status"] = "Service is offline: " + reason
        status_data["mq"] = mq_status_data

        return loopchain_pb2.StatusReply(
            status=json.dumps(status_data),
            block_height=status_data["block_height"],
            total_tx=status_data["total_tx"],
            unconfirmed_block_height=status_data["unconfirmed_block_height"],
            is_leader_complaining=status_data['leader_complaint'],
            peer_id=status_data['peer_id'])

    def ComplainLeader(self, request: ComplainLeaderRequest, context):
        channel_name = request.channel or conf.LOOPCHAIN_DEFAULT_CHANNEL
        utils.logger.info(f"ComplainLeader() complain_vote = {request.complain_vote}")

        self._peer_bridge.channel_complain_leader(channel_name, request.complain_vote)

        return loopchain_pb2.CommonReply(response_code=message_code.Response.success, message="success")

    def AddTxList(self, request: loopchain_pb2.TxSendList, context):
        """Add tx to Block Manager

        :param request:
        :param context:
        :return:
        """
        utils.logger.spam(f"AddTxList() try validate_dumped_tx_message")
        channel_name = request.channel or conf.LOOPCHAIN_DEFAULT_CHANNEL

        self._peer_bridge.channel_tx_receiver_add_tx_list(channel_name, request)
        return loopchain_pb2.CommonReply(response_code=message_code.Response.success, message="success")

    def AnnounceUnconfirmedBlock(self, request, context):
        """Send the UnconfirmedBlock includes collected transactions to reps and request to verify it.

        :param request:
        :param context:
        :return:
        """
        channel_name = request.channel or conf.LOOPCHAIN_DEFAULT_CHANNEL
        utils.logger.debug(f"AnnounceUnconfirmedBlock() channel = {channel_name}")

        try:
            round_ = request.round_
        except AttributeError:
            round_ = 0

        self._peer_bridge.channel_announce_unconfirmed_block(channel_name, request.block, round_)
        return loopchain_pb2.CommonReply(response_code=message_code.Response.success, message="success")

    def BlockSync(self, request, context):
        # Peer To Peer
        channel_name = request.channel or conf.LOOPCHAIN_DEFAULT_CHANNEL
        utils.logger.info(
            f"BlockSync() request hash({request.block_hash}) "
            f"request height({request.block_height}) channel({channel_name})")

        response_code, block_height, max_block_height, unconfirmed_block_height, confirm_info, block_dumped = \
            self._peer_bridge.channel_block_sync(channel_name, request.block_hash, request.block_height)

        return loopchain_pb2.BlockSyncReply(
            response_code=response_code,
            block_height=block_height,
            max_block_height=max_block_height,
            confirm_info=confirm_info,
            block=block_dumped,
            unconfirmed_block_height=unconfirmed_block_height)

    def VoteUnconfirmedBlock(self, request, context):
        channel_name = request.channel or conf.LOOPCHAIN_DEFAULT_CHANNEL

        utils.logger.debug(f"VoteUnconfirmedBlock() vote = {request.vote}")

        self._peer_bridge.channel_vote_unconfirmed_block(channel_name, vote_dumped=request.vote)

        return loopchain_pb2.CommonReply(response_code=message_code.Response.success, message="success")
