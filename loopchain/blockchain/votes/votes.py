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
from typing import Iterable, List, Generic, TypeVar, Optional

from loopchain.blockchain.types import ExternalAddress
from loopchain.blockchain.votes import Vote

TVote = TypeVar("TVote", bound=Vote)


class Votes(ABC, Generic[TVote]):
    VoteType: TVote = None

    def __init__(self, reps: Iterable['ExternalAddress'], voting_ratio: float, votes: List[TVote] = None):
        super().__init__()
        self.reps = tuple(reps)
        if votes is None:
            self.votes: List[Optional[TVote]] = [None] * len(self.reps)
        else:
            self.votes = votes
        self.voting_ratio = voting_ratio
        self.quorum = math.ceil(voting_ratio * len(self.reps))

    def add_vote(self, vote: TVote):
        try:
            self.verify_vote(vote)
        except VoteSafeDuplicateError:
            pass
        except VoteError:
            raise
        else:
            index = self.reps.index(vote.rep)
            self.votes[index] = vote

    def verify(self):
        for rep, vote in zip(self.reps, self.votes):
            if not vote:
                continue
            if rep != vote.rep:
                raise RuntimeError(f"Incorrect Rep : {rep}, {vote.rep}"
                                   f"\nreps({self.reps})"
                                   f"\nvotes({self.votes})")
            try:
                self.verify_vote(vote)
            except VoteSafeDuplicateError:
                pass

    def verify_vote(self, vote: TVote):
        vote.verify()

        try:
            index = self.reps.index(vote.rep)
        except ValueError:
            raise VoteNoRightRep(f"This rep({vote.rep.hex_hx()}) has no right to vote"
                                 f"\nreps({self.reps})")

        # FIXME Leave the evidence, Duplicate voting
        if self.votes[index]:
            if self.votes[index].result() == vote.result():
                # It should be checked last.
                raise VoteSafeDuplicateError
            else:
                raise VoteDuplicateError(f"Duplicate voting. {self.votes[index]}, {vote}")

    @abstractmethod
    def is_completed(self):
        raise NotImplementedError

    @abstractmethod
    def get_result(self):
        raise NotImplementedError

    def get_majority(self):
        counter = Counter(vote.result() for vote in self.votes if vote)
        majorities = counter.most_common()
        return majorities

    def get_summary(self):
        def _fill_space(left_str):
            return ' ' * (length - len(str(left_str)))

        length = 8
        counter = Counter(vote.result() for vote in self.votes if vote)
        for k, v in counter.items():
            length = max(length, len(str(k)))
        length += 1

        msg = "Votes\n"
        for k, v in counter.items():
            msg += f"{k} {_fill_space(k)}: {v}/{len(self.reps)}\n"

        empty_count = sum(1 for vote in self.votes if not vote)
        msg += f"Empty {_fill_space('Empty')}: {empty_count}/{len(self.reps)}\n"
        msg += f"Result {_fill_space('Result')}: {self.get_result()}\n"
        msg += f"Quorum {_fill_space('Quorum')}: {self.quorum}\n"
        return msg

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
    def serialize_votes(cls, votes: List[TVote]) -> list:
        return [vote.serialize() if vote else None for vote in votes]

    @classmethod
    def deserialize_votes(cls, votes_data: list):
        return [cls.VoteType.deserialize(vote_data) if vote_data is not None else None
                for vote_data in votes_data]


class VoteSafeDuplicateError(Exception):
    pass


class VoteError(Exception):
    pass


class VoteNoRightRep(VoteError):
    pass


class VoteDuplicateError(VoteError):
    pass
