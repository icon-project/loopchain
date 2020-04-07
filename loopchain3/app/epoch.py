import math
from typing import Sequence, Type

from lft.consensus.messages.data import Data
from lft.consensus.epoch import Epoch
from lft.consensus.messages.vote import Vote
from lft.consensus.exceptions import InvalidProposer, InvalidVoter

__all__ = ("RotateEpoch", )


class RotateEpoch(Epoch):
    def __init__(self, num: int, voters: Sequence[bytes], rotate_bound: int = 1):
        self._num = num
        self._rotate_bound = rotate_bound
        self._voters = tuple(voters)
        self._voters_num = len(self._voters)

    @property
    def voters(self) -> Sequence[bytes]:
        return self._voters

    @property
    def voters_num(self) -> int:
        return self._voters_num

    @property
    def num(self) -> int:
        return self._num

    @property
    def quorum_num(self) -> int:
        return math.ceil(self.voters_num * 0.67)

    def verify_data(self, data: Data):
        self.verify_proposer(data.proposer_id, data.round_num)

    def verify_vote(self, vote: Vote, vote_index: int = -1):
        if isinstance(vote, Vote):
            self.verify_voter(vote.voter_id, vote_index)

    def verify_proposer(self, proposer_id: bytes, round_num: int):
        expected = self.get_proposer_id(round_num)
        if proposer_id != expected:
            raise InvalidProposer(proposer_id, expected)

    def verify_voter(self, voter: bytes, vote_index: int = -1):
        if vote_index >= 0:
            expected = self.get_voter_id(vote_index)
            if voter != expected:
                raise InvalidVoter(voter, expected)
        else:
            if voter not in self._voters:
                raise InvalidVoter(voter, bytes(0))

    def get_proposer_id(self, round_num: int) -> bytes:
        if len(self._voters) == 0:
            return b''
        else:
            return self._voters[round_num // self._rotate_bound % len(self._voters)]

    def get_voter_id(self, vote_index: int):
        return self._voters[vote_index]

    def get_voters_id(self) -> Sequence[bytes]:
        return self._voters

    def _serialize(self) -> dict:
        return {
            "num": self.num,
            "rotate_bound": self._rotate_bound,
            "voters": self.voters
        }

    @classmethod
    def _deserialize(cls: Type['RotateEpoch'], **kwargs) -> 'RotateEpoch':
        return RotateEpoch(**kwargs)

    def __eq__(self, other):
        if isinstance(other, RotateEpoch):
            if self.voters == other.voters and self.num == other.num and self.quorum_num == other.quorum_num:
                if self._rotate_bound == other._rotate_bound:
                    return True
        return False
