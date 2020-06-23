import math
from typing import TYPE_CHECKING, Sequence

from lft.consensus.epoch import Epoch
from lft.consensus.exceptions import InvalidProposer, InvalidVoter
from lft.consensus.messages.data import Data

from loopchain import configure_default as conf
from loopchain.blockchain.types import ExternalAddress

if TYPE_CHECKING:
    from loopchain.blockchain.votes.v1_0.vote import BlockVote


class LoopchainEpoch(Epoch):
    def __init__(self, num: int, voters: Sequence[ExternalAddress], rotate_bound=None):
        """Represents a set of validators.

        :param num: A epoch number which should be incremented when the validator set is changed.
        :param voters: A group of validators in this epoch.
        :param rotate_bound: A number that decides how many blocks can be proposed per each proposer.
            If round num reaches to the rotate_bound, then the proposer will be changed.
        """
        self._num: int = num
        self._rotate_bound: int = rotate_bound if rotate_bound else conf.MAX_MADE_BLOCK_COUNT
        self._voters: Sequence[ExternalAddress] = tuple(voters)

        # Cached
        self._voters_num = len(self._voters)

    def __repr__(self):
        return f"{self.__class__.__name__}" \
               f"(num={self._num}, " \
               f"rotate_bound={self._rotate_bound}, " \
               f"voters={[voter.hex_hx() for voter in self._voters]})"

    @property
    def num(self) -> int:
        """Unique index of this epoch."""
        return self._num

    @property
    def quorum_num(self) -> int:
        return math.ceil(self.voters_num * conf.VOTING_RATIO)

    @property
    def voters_num(self) -> int:
        return self._voters_num

    @property
    def voters(self) -> Sequence[ExternalAddress]:
        return self._voters

    def verify_data(self, data: Data):
        # Not used in the library.
        pass

    def verify_vote(self, vote: 'BlockVote', vote_index: int = -1):
        # Not used in the library.
        pass

    def verify_proposer(self, proposer_id: bytes, round_num: int):
        expected_proposer = self.get_proposer_id(round_num)
        if proposer_id != expected_proposer and not self._is_genesis_epoch():
            raise InvalidProposer(proposer_id, expected_proposer)

    def _is_genesis_epoch(self):
        return len(self._voters) == 0

    def verify_voter(self, voter: bytes, vote_index: int = -1):
        """Check that the voter is valid or not.

        If `vote_index` is supplied, then verify the voter with its order of validators.
        If `vote_index` is not supplied, then verify only its presence in validators and ignore its order.
        """
        if vote_index >= 0:
            expected_voter = self._voters[vote_index]
            if voter != expected_voter:
                raise InvalidVoter(voter, expected_voter)
        else:
            if voter not in self._voters:
                # TODO: Need for LFT to provide `VoterError` or something else.
                raise InvalidVoter(voter, ExternalAddress.empty())

    def get_proposer_id(self, round_num: int) -> ExternalAddress:
        if len(self._voters) == 0:
            return ExternalAddress.empty()  # TODO: Need to check possible conflicts to IISS Prep changed protocol.
        else:
            return self._voters[round_num // self._rotate_bound % len(self._voters)]

    def get_voter_id(self, vote_index: int) -> ExternalAddress:
        # Not used in the library.
        pass

    def get_voters_id(self) -> Sequence[ExternalAddress]:
        return self._voters

    def __eq__(self, other) -> bool:
        if isinstance(other, self.__class__):
            if self.voters == other.voters and self.num == other.num and self.quorum_num == other.quorum_num:
                if self._rotate_bound == other._rotate_bound:
                    return True
        return False
