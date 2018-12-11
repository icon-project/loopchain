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
from loopchain.baseservice import ObjectManager
from loopchain.blockchain import Block, Vote


class CandidateBlockSetBlock(Exception):
    pass


class CandidateBlock:
    def __init__(self, block_hash):
        """Recommend use factory methods(from_*) instead direct this.

        """
        self.hash = block_hash
        if ObjectManager().channel_service:
            audience = ObjectManager().channel_service.peer_manager
        else:
            audience = None
        self.votes = Vote(block_hash.hex(), audience)
        self.__block = None

    @classmethod
    def from_hash(cls, block_hash):
        candidate_block = CandidateBlock(block_hash)
        candidate_block.hash = block_hash
        return candidate_block

    @classmethod
    def from_block(cls, block: Block):
        candidate_block = CandidateBlock(block.header.hash)
        candidate_block.block = block
        return candidate_block

    def add_vote(self):
        pass

    @property
    def block(self):
        return self.__block

    @block.setter
    def block(self, block: Block):
        if self.hash != block.header.hash:
            raise CandidateBlockSetBlock
        else:
            self.__block = block


class CandidateBlocks:
    def __init__(self):
        self.blocks = {}  # {block_hash : CandidateBlocks}

    def add_vote(self, block_hash, peer_id, vote):
        pass

    def add_block(self, block: Block):
        self.blocks[block.header.hash] = block

    def remove_block(self, block_hash):
        self.blocks.pop(block_hash, None)
