import asyncio

import time
from lft.consensus.events import ReceiveDataEvent, ReceiveVoteEvent
from typing import TYPE_CHECKING, Dict

from loopchain import configure as conf
from loopchain.blockchain.blocks.v1_0 import Block
from loopchain.blockchain.votes.v1_0 import BlockVote
from loopchain.channel.channel_property import ChannelProperty
from loopchain.protos import loopchain_pb2, loopchain_pb2_grpc
from loopchain.tools.grpc_helper import GRPCHelper

if TYPE_CHECKING:
    from loopchain.peer.block_manager import BlockManager
    from lft.event import EventSystem

RAISE_EVENT_INTERVAL: int = 3
NONE_VOTE_HEIGHT: int = 0


class Syncer:
    def __init__(self, block_manager: 'BlockManager', event_system: 'EventSystem'):
        self._block_manager = block_manager
        self.__blockchain = self._block_manager.blockchain
        self._event_system: 'EventSystem' = event_system
        self._data_info_other_nodes: Dict[int, list] = {}
        self._vote_info_other_nodes: Dict[int, list] = {}
        self._request_history_list = {}
        self._target_index = 0
        self._stub_list = []
        self._max_height_in_nodes = self.__blockchain.block_height
        self.management_stub()

        if self.__blockchain.last_block:
            reps_hash = self.__blockchain.get_reps_hash_by_header(self.__blockchain.last_block.header)
        else:
            reps_hash = ChannelProperty().crep_root_hash
        self._rep_targets = self.__blockchain.find_preps_targets_by_roothash(reps_hash)

    def management_stub(self, status="init"):
        if "update" == status:
            self._stub_list = []
            self._target_index = 0

        target_list = self._block_manager.get_target_list()
        for target in target_list:
            channel = GRPCHelper().create_client_channel(target)
            self._stub_list.append(loopchain_pb2_grpc.PeerServiceStub(channel))

    async def sync_start(self):
        while True:
            await self._request_block()
            await self._raise_event()

    async def _request_block(self):
        def _request(index: int, height: int):
            peer_stub = self._stub_list[index]

            peer_stub.BlockRequest(loopchain_pb2.PeerHeight(
                peer=ChannelProperty().peer_target,
                channel=self._block_manager.channel_name,
                height=height
            ), conf.GRPC_TIMEOUT)

        # Sync mode check
        # LFT is two step process. So It need to wait for a height of at least 2.
        gap = self._max_height_in_nodes-self.__blockchain.block_height
        if gap < RAISE_EVENT_INTERVAL:
            return

        goal = min(conf.CITIZEN_ASYNC_RESULT_MAX_SIZE+1, self._max_height_in_nodes-RAISE_EVENT_INTERVAL)
        for i in range(1, goal):
            height = self.__blockchain.block_height + i
            if height in self._request_history_list:
                during_request_time = time.time()-self._request_history_list[height][1]
                if during_request_time > conf.LFT_SYNC_REQUEST_WAIT:
                    retry_target_index = (self._request_history_list[height][0] + 1) % len(self._stub_list)
                    _request(retry_target_index, height)
                    self._request_history_list[height] = [retry_target_index, time.time()]
            else:
                try:
                    _request(self._target_index, height)
                except IndexError:
                    self._target_index = 0
                else:
                    self._request_history_list[height] = [self._target_index, time.time()]
                    self._target_index = (self._target_index+1) % len(self._stub_list)

            await asyncio.sleep(0)

    def _append_block_if_not_exists(self, height: int, dict_info: Dict, data_object):
        if height not in dict_info:
            dict_info[height] = []

        dict_info[height].append(data_object)

    def receive_vote(self, vote: 'BlockVote'):
        height = vote.block_height
        self._max_height_in_nodes = max(height, self._max_height_in_nodes)

        if abs(self.__blockchain.block_height-height) < conf.CITIZEN_ASYNC_RESULT_MAX_SIZE:
            self._append_block_if_not_exists(height, self._vote_info_other_nodes, vote)

    def receive_data(self, block_data: 'Block'):
        height = block_data.header.height
        self._max_height_in_nodes = max(height, self._max_height_in_nodes)

        diff_height_info = abs(self.__blockchain.block_height-self._max_height_in_nodes)
        if diff_height_info < conf.CITIZEN_ASYNC_RESULT_MAX_SIZE:
            self._append_block_if_not_exists(height, self._data_info_other_nodes, block_data)

            # Check Sync mode
            # If height make different 3 value between to written block height and to received block height,
            # It information is to responded for Synchronize.
            # So It need to raise to dilast_block.header.heightvide Block information and Vote Information.
            if RAISE_EVENT_INTERVAL < diff_height_info:
                for vote in block_data.prev_votes:
                    self.receive_vote(vote)

    def _raise_vote(self, height: int):
        while self._vote_info_other_nodes[height]:
            vote_info = self._vote_info_other_nodes[height].pop()
            event = ReceiveVoteEvent(vote_info)
            self._event_system.simulator.raise_event(event)

        del self._vote_info_other_nodes[height]

    async def _raise_event(self):
        # LFT is two step event.
        # It need to raise event two block information after to written block height.
        for i in range(1, RAISE_EVENT_INTERVAL):
            height = self.__blockchain.block_height+i
            if height in self._data_info_other_nodes:
                block_info = self._data_info_other_nodes[height].pop()
                event = ReceiveDataEvent(block_info)
                self._event_system.simulator.raise_event(event)
                del self._data_info_other_nodes[height]

            await asyncio.sleep(0)

            if height in self._vote_info_other_nodes:
                self._raise_vote(height)

            if NONE_VOTE_HEIGHT in self._vote_info_other_nodes:
                self._raise_vote(NONE_VOTE_HEIGHT)

            await asyncio.sleep(0)

        await asyncio.sleep(0)

        if self.__blockchain.block_height in self._request_history_list:
            del self._request_history_list[self.__blockchain.block_height]

        last_block = self.__blockchain.last_block
        if last_block is not None:
            current_rep_targets = self.__blockchain.get_reps_hash_by_header(last_block.header)
            if self._rep_targets != current_rep_targets:
                self.management_stub(status="update")
                self._rep_targets = current_rep_targets
