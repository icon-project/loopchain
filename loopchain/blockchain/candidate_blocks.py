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
from loopchain import configure as conf
from loopchain.baseservice import ObjectManager
from loopchain.blockchain import Block, Vote, Hash32


class CandidateBlockSetBlock(Exception):
    pass


class CandidateBlock:
    def __init__(self, block_hash: Hash32):
        """Recommend use factory methods(from_*) instead direct this.

        """
        if ObjectManager().channel_service:
            audience = ObjectManager().channel_service.peer_manager
        else:
            audience = None

        self.start_time = util.get_time_stamp()  # timestamp
        self.hash = block_hash
        self.vote = Vote(block_hash.hex(), audience)
        self.__block = None

    @classmethod
    def from_hash(cls, block_hash: Hash32):
        candidate_block = CandidateBlock(block_hash)
        candidate_block.hash = block_hash
        return candidate_block

    @classmethod
    def from_block(cls, block: Block):
        candidate_block = CandidateBlock(block.header.hash)
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
        self.blocks = {}  # {block_hash(Hash32) : CandidateBlock}
        self.__blocks_lock = threading.Lock()

    def add_vote(self, block_hash: Hash32, group_id, peer_id, vote):
        with self.__blocks_lock:
            if block_hash not in self.blocks:
                self.blocks[block_hash] = CandidateBlock.from_hash(block_hash)

        self.blocks[block_hash].vote.add_vote(group_id, peer_id, vote)

    def get_vote_result(self, block_hash):
        return self.blocks[block_hash].vote.get_result(block_hash.hex(), conf.VOTING_RATIO)

    def add_block(self, block: Block):
        with self.__blocks_lock:
            if block.header.hash not in self.blocks:
                self.blocks[block.header.hash] = CandidateBlock.from_block(block)
            else:
                self.blocks[block.header.hash].block = block

    def remove_block(self, block_hash):
        if self.blocks[block_hash].block is not None:
            prev_block_hash = self.blocks[block_hash].block.header.prev_hash

            for _block_hash in list(self.blocks.keys()):
                if self.blocks[_block_hash].block is not None:
                    if self.blocks[_block_hash].block.header.prev_hash == prev_block_hash:
                        self.blocks.pop(_block_hash, None)
                else:
                    if util.diff_in_seconds(self.blocks[_block_hash].start_time) > conf.CANDIDATE_BLOCK_TIMEOUT:
                        continue
