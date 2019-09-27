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

from typing import Iterable, List, Dict

from loopchain.blockchain.types import Hash32, ExternalAddress
from loopchain.blockchain.votes import Votes as BaseVotes
from loopchain.blockchain.votes.v0_1a import BlockVote, LeaderVote


class BlockVotes(BaseVotes[BlockVote]):
    VoteType = BlockVote

    def __init__(self, reps: Iterable['ExternalAddress'], voting_ratio: float,
                 block_height: int, round_: int, block_hash: Hash32, votes: List[BlockVote] = None):
        self.block_height = block_height
        self.round = round_
        self.block_hash = block_hash
        super().__init__(reps, voting_ratio, votes)

    def verify_vote(self, vote: BlockVote):
        if vote.block_height != self.block_height:
            raise RuntimeError(f"Vote block_height not match. {vote.block_height} != {self.block_height}\n"
                               f"{vote}")

        if vote.round_ != self.round:
            raise RuntimeError(f"Vote round not match. {vote.round_} != {self.round}\n"
                               f"{vote}")

        if vote.block_hash != self.block_hash and vote.block_hash != Hash32.empty():
            raise RuntimeError(f"Vote block_hash not match. {vote.block_hash} != {self.block_hash}\n"
                               f"{vote}")
        super().verify_vote(vote)

    def is_completed(self):
        return self.get_result() is not None

    def get_result(self):
        true_vote_count = sum(1 for vote in self.votes
                              if vote and vote.block_hash == self.block_hash)
        if true_vote_count >= self.quorum:
            return True

        false_vote_count = sum(1 for vote in self.votes
                               if vote and vote.block_hash == Hash32.empty())
        if false_vote_count >= len(self.reps) - self.quorum + 1:
            return False
        return None

    def get_summary(self):
        msg = super().get_summary()
        msg += f"block height({self.block_height})\n"
        msg += f"round({self.round})\n"
        msg += f"block hash({self.block_hash.hex_0x()})"
        return msg

    def __eq__(self, other: 'BlockVotes'):
        return (
            super().__eq__(other) and
            self.block_hash == other.block_hash and
            self.block_height == other.block_height and
            self.round == other.round
        )

    def __repr__(self):
        return (
            f"{self.__class__.__qualname__}(reps={self.reps!r}, voting_ratio={self.voting_ratio!r}, "
            f"block_height={self.block_height!r}, round={self.round!r}, "
            f"block_hash={self.block_hash!r}, votes={self.votes!r})"
        )


class LeaderVotes(BaseVotes[LeaderVote]):
    VoteType = LeaderVote

    def __init__(self, reps: Iterable['ExternalAddress'], voting_ratio: float, block_height: int, round_: int,
                 old_leader: ExternalAddress, votes: List[LeaderVote] = None):
        self.block_height = block_height
        self.round = round_
        self.old_leader = old_leader
        super().__init__(reps, voting_ratio, votes)

    def verify_vote(self, vote: LeaderVote):
        if vote.block_height != self.block_height:
            raise RuntimeError(f"Vote block_height not match. {vote.block_height} != {self.block_height}\n"
                               f"{vote}")

        if vote.round_ != self.round:
            raise RuntimeError(f"Vote round not match. {vote.round_} != {self.round}\n"
                               f"{vote}")

        if vote.old_leader != self.old_leader:
            raise RuntimeError(f"Vote old_leader not match. {vote.old_leader} != {self.old_leader}\n"
                               f"{vote}")
        super().verify_vote(vote)

    def is_completed(self):
        majority_pair = self.get_majority()
        if majority_pair:
            majority_count = majority_pair[1]
            if majority_count >= self.quorum:
                return True

            empty_count = self.votes.count(None)
            if majority_count + empty_count < self.quorum:
                # It determines the majority of this votes cannot reach the quorum
                return True
        return False

    def get_result(self):
        majority_pair = self.get_majority()
        if majority_pair:
            majority_value = majority_pair[0]
            majority_count = majority_pair[1]
            if majority_count >= self.quorum:
                return majority_value
        return None

    def get_summary(self):
        msg = super().get_summary()
        msg += f"block height({self.block_height})\n"
        msg += f"round({self.round})\n"
        msg += f"old leader({self.old_leader.hex_hx()})"
        return msg

    def __eq__(self, other: 'LeaderVotes'):
        return (
                super().__eq__(other) and
                self.block_height == other.block_height and
                self.round == other.round and
                self.old_leader == other.old_leader
        )

    def __repr__(self):
        return (
            f"{self.__class__.__qualname__}(reps={self.reps!r}, voting_ratio={self.voting_ratio!r}, "
            f"block_height={self.block_height!r}, round={self.round!r}, "
            f"old_leader={self.old_leader!r}, votes={self.votes!r})"
        )

    # noinspection PyMethodOverriding
    @classmethod
    def deserialize(cls, votes_data: List[Dict], voting_ratio: float):
        if votes_data:
            votes = [LeaderVote.deserialize(vote_data) for vote_data in votes_data]
            reps = [vote.rep for vote in votes]
            votes_instance = cls(reps, voting_ratio, votes[0].block_height, votes[0].round_, votes[0].old_leader)
            for vote in votes:
                index = reps.index(vote.rep)
                votes_instance.votes[index] = vote
            return votes_instance
        else:
            return cls([], voting_ratio, -1, -1, ExternalAddress.empty())
