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

from typing import Iterable
from loopchain.blockchain.types import Hash32, ExternalAddress
from loopchain.blockchain.votes import Votes as BaseVotes
from loopchain.blockchain.votes.v0_1a import BlockVote, LeaderVote


class BlockVotes(BaseVotes[BlockVote]):
    VoteType = BlockVote

    def __init__(self, reps: Iterable['ExternalAddress'], voting_ratio: float,
                 block_height: int, block_hash: Hash32):
        super().__init__(reps, voting_ratio)
        self.block_height = block_height
        self.block_hash = block_hash

    def verify(self, vote: BlockVote):
        super().verify(vote)

        if vote.block_height != self.block_height:
            raise RuntimeError(f"Vote block_height not match. {vote.block_height} != {self.block_height}")

        if vote.block_hash != self.block_hash and vote.block_hash != Hash32.empty():
            raise RuntimeError(f"Vote block_hash not match. {vote.block_hash} != {self.block_hash}")

    # noinspection PyMethodOverriding
    @classmethod
    def deserialize(cls, votes_data: list, reps: Iterable['ExternalAddress'], voting_ratio: float,
                    block_height: int, block_hash: Hash32):
        return super().deserialize(votes_data, reps, voting_ratio,
                                   block_height=block_height, block_hash=block_hash)


class LeaderVotes(BaseVotes[LeaderVote]):
    VoteType = LeaderVote

    def __init__(self, reps: Iterable['ExternalAddress'], voting_ratio: float,
                 block_height: int, old_leader: ExternalAddress):
        super().__init__(reps, voting_ratio)
        self.block_height = block_height
        self.old_leader = old_leader

    def verify(self, vote: LeaderVote):
        super().verify(vote)

        if vote.block_height != self.block_height:
            raise RuntimeError(f"Vote block_height not match. {vote.block_height} != {self.block_height}")

        if vote.old_leader != self.old_leader:
            raise RuntimeError(f"Vote old_leader not match. {vote.old_leader} != {self.old_leader}")

    # noinspection PyMethodOverriding
    @classmethod
    def deserialize(cls, votes_data: list, reps: Iterable['ExternalAddress'], voting_ratio: float,
                    block_height: int, old_leader: ExternalAddress, new_leader: ExternalAddress):
        return super().deserialize(votes_data, reps, voting_ratio,
                                   block_height=block_height, old_leader=old_leader, new_leader=new_leader)
