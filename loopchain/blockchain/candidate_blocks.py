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
"""Candidate Blocks"""
import logging
import threading
import loopchain.utils as util

from typing import Dict
from loopchain import configure as conf
from loopchain.baseservice import ObjectManager
from loopchain.blockchain.types import Hash32, ExternalAddress
from loopchain.blockchain.votes.v0_1a import BlockVote, BlockVotes
from loopchain.blockchain.blocks import Block


__all__ = ("CandidateBlockSetBlock", "CandidateBlock", "CandidateBlocks")


class CandidateBlockSetBlock(Exception):
    pass


class CandidateBlock:
    def __init__(self, block_hash: Hash32, block_height: int):
        """Recommend use factory methods(from_*) instead direct this.

        """
        if ObjectManager().channel_service:
            audience = ObjectManager().channel_service.peer_manager.peer_list[conf.ALL_GROUP_ID]
        else:
            audience = {}

        self.start_time = util.get_time_stamp()  # timestamp
        self.hash = block_hash
        self.height = block_height

        rep_info = sorted(audience.values(), key=lambda peer: peer.order)
        reps = [ExternalAddress.fromhex(rep.peer_id) for rep in rep_info]
        self.votes = BlockVotes(reps, conf.VOTING_RATIO, block_height, block_hash)

        self.__block = None

    @classmethod
    def from_hash(cls, block_hash: Hash32, block_height: int):
        candidate_block = CandidateBlock(block_hash, block_height)
        return candidate_block

    @classmethod
    def from_block(cls, block: Block):
        candidate_block = CandidateBlock(block.header.hash, block.header.height)
        candidate_block.block = block
        return candidate_block

    @property
    def block(self):
        return self.__block

    @block.setter
    def block(self, block: Block):
        if self.hash != block.header.hash:
            raise CandidateBlockSetBlock
        else:
            logging.debug(f"set block({block.header.hash.hex()}) in CandidateBlock")
            self.__block = block


class CandidateBlocks:
    def __init__(self):
        self.blocks: Dict[Hash32, CandidateBlock] = {}
        self.__blocks_lock = threading.Lock()

    def add_vote(self, vote: BlockVote):
        with self.__blocks_lock:
            if vote.block_hash not in self.blocks:
                # util.logger.debug(f"-------------block_hash({block_hash}) self.blocks({self.blocks})")
                self.blocks[vote.block_hash] = CandidateBlock.from_hash(vote.block_hash, vote.block_height)
        self.blocks[vote.block_hash].votes.add_vote(vote)

    def get_vote(self, block_hash):
        return self.blocks[block_hash].votes

    def add_block(self, block: Block):
        with self.__blocks_lock:
            if block.header.hash not in self.blocks:
                self.blocks[block.header.hash] = CandidateBlock.from_block(block)
            else:
                self.blocks[block.header.hash].block = block

    # height 정보가 있어서 height를 통채로 날려야 할 것 같다
    def remove_block(self, block_hash):
        if self.blocks[block_hash].block:
            prev_block_hash = self.blocks[block_hash].block.header.prev_hash

            for _block_hash in list(self.blocks.keys()):
                if self.blocks[_block_hash].block:
                    if self.blocks[_block_hash].block.header.prev_hash == prev_block_hash:
                        self.blocks.pop(_block_hash, None)
                        continue
                if util.diff_in_seconds(self.blocks[_block_hash].start_time) >= conf.CANDIDATE_BLOCK_TIMEOUT:
                    self.blocks.pop(_block_hash, None)
