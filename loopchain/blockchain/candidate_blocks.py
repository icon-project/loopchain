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
import loopchain.utils as util
from loopchain.blockchain import Block


class CandidateBlockSetBlock(Exception):
    pass


class CandidateBlock:
    def __init__(self):
        """Recommend use factory methods(from_*) instead direct this.

        """
        self.hash = ""
        self.votes = {}
        self.__block = None

    @classmethod
    def from_hash(cls, block_hash):
        candidate_block = CandidateBlock()
        candidate_block.hash = block_hash
        return candidate_block

    @classmethod
    def from_block(cls, block: Block):
        candidate_block = CandidateBlock()
        candidate_block.block = block
        return candidate_block

    def add_vote(self):
        pass

    @property
    def block(self):
        return self.__block

    @block.setter
    def block(self, block: Block):
        util.logger.spam(f"setter")
        if self.hash != "" and self.hash != block.header.hash:
            raise CandidateBlockSetBlock
        else:
            self.hash = block.header.hash
            self.__block = block


class CandidateBlocks:
    def __init__(self):
        self.blocks = {}  # {block_hash : CandidateBlocks}

    def add_vote(self, block_hash, vote):
        pass

    def add_block(self, block):
        pass

    def remove_block(self, block_hash):
        pass
