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

import math
from abc import ABC
from collections import Counter
from typing import Iterable, List, Generic, TypeVar
from loopchain.blockchain.types import ExternalAddress
from loopchain.blockchain.votes import Vote

TVote = TypeVar("TVote", bound=Vote)


class Votes(ABC, Generic[TVote]):
    VoteType: TVote = None

    def __init__(self, reps: Iterable['ExternalAddress'], voting_ratio: float):
        super().__init__()
        self.reps = tuple(reps)
        self.votes: List[TVote] = [None] * len(self.reps)
        self.voting_ratio = voting_ratio
        self.quorum = math.ceil(voting_ratio * len(self.reps))

    def add_vote(self, vote: TVote):
        try:
            self.verify(vote)
        except VoteSafeDuplicateError:
            return

        index = self.reps.index(vote.rep)
        self.votes[index] = vote

    def verify(self, vote: TVote):
        # IndexError
        index = self.reps.index(vote.rep)

        # FIXME Leave the evidence, Duplicate voting
        if self.votes[index] is not None:
            if self.votes[index].result() == vote.result():
                raise VoteSafeDuplicateError
            else:
                raise VoteDuplicateError(f"Duplicate voting. {self.votes[index]}, {vote}")

        vote.verify()

    def get_majority(self):
        majority_pair = self._get_majority()
        if majority_pair:
            majority_value = majority_pair[0]
            majority_count = majority_pair[1]
            if majority_count >= self.quorum:
                return majority_value
        return None

    def _get_majority(self):
        counter = Counter(vote.result() for vote in self.votes if vote is not None)
        majorities = counter.most_common(1)
        return majorities[0] if majorities else None

    def completed(self):
        majority_pair = self._get_majority()
        if majority_pair:
            majority_count = majority_pair[1]
            if majority_count >= self.quorum:
                return True

            empty_count = sum(1 for vote in self.votes if vote is None)
            if majority_count + empty_count < self.quorum:
                # It determines the majority of this votes cannot reach the quorum
                return True
        return False

    def serialize(self) -> list:
        return [vote.serialize() for vote in self.votes]

    def __str__(self):
        def _fill_space(left_str):
            return ' ' * (length - len(str(left_str)))

        length = 8
        counter = Counter(vote.result() for vote in self.votes if vote is not None)
        for k, v in counter.items():
            length = max(length, len(str(k)))
        length += 1

        msg = "Votes\n"
        for k, v in counter.items():
            msg += f"{k} {_fill_space(k)}: {v}/{len(self.reps)}\n"

        empty_count = sum(1 for vote in self.votes if vote is None)
        msg += f"Empty {_fill_space('Empty')}: {empty_count}/{len(self.reps)}\n"
        msg += f"Majority {_fill_space('Majority')}: {self.get_majority()}\n"
        msg += f"Quorum {_fill_space('Quorum')}: {self.quorum}\n"
        return msg

    @classmethod
    def deserialize(cls, votes_data: list, reps: Iterable['ExternalAddress'], voting_ratio: float, **kwargs):
        # noinspection PyArgumentList
        votes = cls(reps, voting_ratio, **kwargs)
        for vote_data in votes_data:
            if vote_data:
                vote = cls.VoteType.deserialize(vote_data)
                votes.add_vote(vote)


class VoteSafeDuplicateError(Exception):
    pass


class VoteDuplicateError(Exception):
    pass
