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
from typing import Dict, List

import loopchain.utils as util
from loopchain import configure as conf
from loopchain.baseservice import ObjectManager
from loopchain.blockchain.blocks import Block
from loopchain.blockchain.types import Hash32
from loopchain.blockchain.votes.v0_1a import BlockVote, BlockVotes
from loopchain.blockchain.votes.votes import VoteError

__all__ = ("CandidateBlockSetBlock", "CandidateBlock", "CandidateBlocks")


class CandidateBlockSetBlock(Exception):
    pass


class CandidateBlock:
    def __init__(self, block_hash: Hash32, block_height: int):
        """Recommend use factory methods(from_*) instead direct this.

        """
        self.votes: dict[int, BlockVotes] = {}
        self.votes_buffer: List[BlockVote] = []
        self.start_time = util.get_time_stamp()  # timestamp
        self.hash = block_hash
        self.height = block_height
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

            reps = self.__get_reps()
            self.votes[0] = BlockVotes(reps, conf.VOTING_RATIO, self.height, 0, self.hash)
            for vote in self.votes_buffer:
                try:
                    if not self.votes.get(vote.round_):
                        self.votes[vote.round_] = \
                            BlockVotes(reps, conf.VOTING_RATIO, self.height, vote.round_, self.hash)
                    self.votes[vote.round_].add_vote(vote)
                except VoteError as e:
                    util.logger.info(e)
            self.votes_buffer.clear()

    def __get_reps(self):
        channel_service = ObjectManager().channel_service
        if channel_service:
            return channel_service.block_manager.blockchain.find_preps_addresses_by_header(self.__block.header)
        else:
            return []

    def add_vote(self, vote: BlockVote):
        if self.votes:
            if not self.votes.get(vote.round_):
                self.votes[vote.round_] = \
                    BlockVotes(self.__get_reps(), conf.VOTING_RATIO, self.height, vote.round_, self.hash)
            try:
                self.votes[vote.round_].add_vote(vote)
            except VoteError as e:
                util.logger.info(e)
                return
        else:
            self.votes_buffer.append(vote)


class CandidateBlocks:
    def __init__(self, blockchain):
        self.blocks: Dict[Hash32, CandidateBlock] = {}
        self.__blocks_lock = threading.Lock()
        self._blockchain = blockchain

    def add_vote(self, vote: BlockVote):
        with self.__blocks_lock:
            if vote.block_hash != Hash32.empty() and vote.block_hash not in self.blocks:
                # util.logger.debug(f"-------------block_hash({block_hash}) self.blocks({self.blocks})")
                self.blocks[vote.block_hash] = CandidateBlock.from_hash(vote.block_hash, vote.block_height)

        if vote.block_hash != Hash32.empty():
            self.blocks[vote.block_hash].add_vote(vote)
        else:
            for block in self.blocks.values():
                if block.height == vote.block_height:
                    block.add_vote(vote)

    def get_votes(self, block_hash, round_: int):
        votes = self.blocks[block_hash].votes
        return votes.get(round_) if votes else votes

    def add_block(self, block: Block):
        if block.header.height != self._blockchain.block_height + 1:
            util.logger.warning(
                f"Candidate block height must be ({self._blockchain.block_height})"
                f"\nyou tried add block height({block.header.height})")
            return

        with self.__blocks_lock:
            if block.header.hash not in self.blocks:
                self.blocks[block.header.hash] = CandidateBlock.from_block(block)
            else:
                self.blocks[block.header.hash].block = block

    def remove_block(self, block_hash):
        if block_hash in self.blocks and self.blocks[block_hash].block:
            prev_block_hash = self.blocks[block_hash].block.header.prev_hash

            for _block_hash in list(self.blocks.keys()):
                if self.blocks[_block_hash].block:
                    if self.blocks[_block_hash].block.header.prev_hash == prev_block_hash:
                        self.blocks.pop(_block_hash, None)
                        continue
                if util.diff_in_seconds(self.blocks[_block_hash].start_time) >= conf.CANDIDATE_BLOCK_TIMEOUT:
                    self.blocks.pop(_block_hash, None)
