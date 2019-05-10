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
from abc import ABC, abstractmethod
from collections import Counter
from typing import Iterable, List, Generic, TypeVar
from loopchain.blockchain.types import ExternalAddress, Signature
from loopchain.blockchain.votes import Vote

TVote = TypeVar("TVote", bound=Vote)


class Votes(ABC, Generic[TVote]):
    VoteType: TVote = None

    def __init__(self, reps: Iterable['ExternalAddress'], voting_ratio: float, votes: List[TVote] = None):
        super().__init__()
        self.reps = tuple(reps)
        if votes is None:
            self.votes: List[TVote] = [self.empty_vote(rep) for rep in self.reps]
        else:
            self.votes = votes
        self.voting_ratio = voting_ratio
        self.quorum = math.ceil(voting_ratio * len(self.reps))

    def add_vote(self, vote: TVote):
        try:
            self.verify_vote(vote)
        except VoteSafeDuplicateError:
            pass
        else:
            index = self.reps.index(vote.rep)
            self.votes[index] = vote

    def verify(self):
        for rep, vote in zip(self.reps, self.votes):
            if self.is_empty_vote(vote):
                continue
            if rep != vote.rep:
                raise RuntimeError(f"Incorrect Rep : {rep}, {vote.rep}")
            try:
                self.verify_vote(vote)
            except VoteSafeDuplicateError:
                pass

    def verify_vote(self, vote: TVote):
        vote.verify()

        index = self.reps.index(vote.rep)

        # FIXME Leave the evidence, Duplicate voting
        if self.votes[index] != self.empty_vote(vote.rep):
            if self.votes[index].result() == vote.result():
                # It should be checked last.
                raise VoteSafeDuplicateError
            else:
                raise VoteDuplicateError(f"Duplicate voting. {self.votes[index]}, {vote}")

    @abstractmethod
    def empty_vote(self, rep: ExternalAddress):
        raise NotImplementedError

    def is_empty_vote(self, vote: Vote):
        return vote.signature == Signature.empty()

    @abstractmethod
    def is_completed(self):
        raise NotImplementedError

    @abstractmethod
    def get_result(self):
        raise NotImplementedError

    def get_majority(self):
        counter = Counter(vote.result() for vote in self.votes if not self.is_empty_vote(vote))
        majorities = counter.most_common(1)
        return majorities[0] if majorities else None

    def get_summary(self):
        def _fill_space(left_str):
            return ' ' * (length - len(str(left_str)))

        length = 8
        counter = Counter(vote.result() for vote in self.votes if not self.is_empty_vote(vote))
        for k, v in counter.items():
            length = max(length, len(str(k)))
        length += 1

        msg = "Votes\n"
        for k, v in counter.items():
            msg += f"{k} {_fill_space(k)}: {v}/{len(self.reps)}\n"

        empty_count = sum(1 for vote in self.votes if self.is_empty_vote(vote))
        msg += f"Empty {_fill_space('Empty')}: {empty_count}/{len(self.reps)}\n"
        msg += f"Result {_fill_space('Result')}: {self.get_result()}\n"
        msg += f"Quorum {_fill_space('Quorum')}: {self.quorum}\n"
        return msg

    def serialize(self) -> list:
        return [vote.serialize() for vote in self.votes]

    def __repr__(self):
        return (
            f"{self.__class__.__qualname__}(reps={self.reps!r}, voting_ratio={self.voting_ratio!r}, "
            f"votes={self.votes!r})"
        )

    def __eq__(self, other: 'Votes'):
        return (
            type(self) == type(other) and
            self.reps == other.reps and
            self.votes == other.votes and
            self.voting_ratio == other.voting_ratio and
            self.quorum == other.quorum
        )

    @classmethod
    def deserialize(cls, votes_data: list, voting_ratio: float, **kwargs):
        raise NotImplementedError


class VoteSafeDuplicateError(Exception):
    pass


class VoteDuplicateError(Exception):
    pass
