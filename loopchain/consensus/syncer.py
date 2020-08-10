import time, asyncio
from typing import TYPE_CHECKING
from loopchain import utils, configure as conf
from loopchain.blockchain.blocks.v1_0 import Block
from loopchain.blockchain.votes.v1_0 import BlockVote
from loopchain.protos import message_code, loopchain_pb2, loopchain_pb2_grpc
from loopchain.tools.grpc_helper import GRPCHelper
from loopchain.channel.channel_property import ChannelProperty

from lft.event import EventSystem
from lft.consensus.events import ReceiveDataEvent, ReceiveVoteEvent

if TYPE_CHECKING:
    from loopchain.peer.block_manager import BlockManager

class Syncer:
    def __init__(self,
                 block_manager: 'BlockManager',
                 event_system: 'EventSystem',
                 last_block_height: int = 0):
        self._block_manager = block_manager
        self._event_system: 'EventSystem' = event_system
        self._last_block_height = last_block_height
        self._data_info_other_nodes: Dict[int, list] = dict()
        self._vote_info_other_nodes: Dict[int, list] = dict()
        self._max_height_in_nodes = last_block_height

        self._request_history_list = dict()
        self._target_idx = 0
        self._stub_list = list()
        self.management_stub()

    def management_stub(self, status: str = 'init'):
        self._target_list = self._block_manager.get_target_list()
        for target in self._target_list:
            channel = GRPCHelper().create_client_channel(target)
            self._stub_list.append(loopchain_pb2_grpc.PeerServiceStub(channel))

    @property
    def last_block_height(self):
        return self._last_block_height

    @last_block_height.setter
    def last_block_height(self, height: int):
        self._last_block_height = height

    async def sync_start(self):
        while True:
            # await self._request_height()
            await self._request_block()
            await self._raise_event()

    async def _request_height(self):
        peer_stub = self._stub_list[self._target]

        response = peer_stub.BlockHeightRequest(loopchain_pb2.HeightRequest(
            peer=ChannelProperty().peer_target,
            channel=self._block_manager.channel_name
        ), conf.GRPC_TIMEOUT)

    async def _request_block(self):
        def _request(idx: int, height: int):
            peer_stub = self._stub_list[idx]

            response = peer_stub.BlockRequest(loopchain_pb2.PeerHeight(
                peer=ChannelProperty().peer_target,
                channel=self._block_manager.channel_name,
                height=height
            ), conf.GRPC_TIMEOUT)

        max_loop = self._max_height_in_nodes-3
        if self._last_block_height < max_loop:
            for i in range(1, min(conf.CITIZEN_ASYNC_RESULT_MAX_SIZE+1, max_loop-self._last_block_height)):
                height = self._last_block_height + i
                if height in self._request_history_list.keys():
                    during_request_time = time.time()-self._request_history_list[height][1]
                    if during_request_time > conf.WAIT_SUB_PROCESS_RETRY_TIMES:
                        retry_target_idx = self._request_history_list[height][0]
                        _request(retry_target_idx, height)
                        self._request_history_list[height] = [retry_target_idx, time.time()]
                else:
                    _request(self._target_idx, height)
                    self._request_history_list[height] = list()
                    self._request_history_list[height] = [self._target_idx, time.time()]
                    self._target_idx = (self._target_idx+1) % len(self._stub_list)

                await asyncio.sleep(0)

    def receive_vote(self, vote: 'BlockVote'):
        height = vote.block_height
        self._max_height_in_nodes = max(height, self._max_height_in_nodes)

        if abs(self._last_block_height-height) < conf.CITIZEN_ASYNC_RESULT_MAX_SIZE:
            if not height in self._vote_info_other_nodes.keys():
                self._vote_info_other_nodes[height] = list()

            self._vote_info_other_nodes[height].append(vote)


    def receive_data(self, block_data: 'Block'):
        height = block_data.header.height
        self._max_height_in_nodes = max(height, self._max_height_in_nodes)

        diff_height_info = abs(self._last_block_height-self._max_height_in_nodes)
        if diff_height_info < conf.CITIZEN_ASYNC_RESULT_MAX_SIZE:
            if not height in self._data_info_other_nodes.keys():
                self._data_info_other_nodes[height] = list()

            self._data_info_other_nodes[height].append(block_data)

            if 3 < diff_height_info:
                for vote in block_data.prev_votes:
                    self.receive_vote(vote)

    async def _raise_event(self):
        for i in range(1, 3):
            height = self._last_block_height+i
            if height in self._data_info_other_nodes.keys():
                block_info = self._data_info_other_nodes[height].pop()
                event = ReceiveDataEvent(block_info)
                self._event_system.simulator.raise_event(event)
                del(self._data_info_other_nodes[height])

            await asyncio.sleep(0)
            if height in self._vote_info_other_nodes.keys():
                while self._vote_info_other_nodes[height]:
                    vote_info = self._vote_info_other_nodes[height].pop()
                    event = ReceiveVoteEvent(vote_info)
                    self._event_system.simulator.raise_event(event)

                del(self._vote_info_other_nodes[height])

            await asyncio.sleep(0)

        fail_height = 0
        if fail_height in self._vote_info_other_nodes.keys():
            while self._vote_info_other_nodes[fail_height]:
                vote_info = self._vote_info_other_nodes[fail_height].pop()
                event = ReceiveVoteEvent(vote_info)
                self._event_system.simulator.raise_event(event)

            del(self._vote_info_other_nodes[fail_height])

        await asyncio.sleep(0)
