import functools
import os
from typing import List, Callable

import pytest

from loopchain.blockchain.types import ExternalAddress, Signature
from loopchain.blockchain.types import Hash32
from loopchain.blockchain.votes import v0_1a
from loopchain.blockchain.votes.votes import Vote
from loopchain.blockchain.votes.votes import VoteDuplicateError
from loopchain.blockchain.votes.votes import VoteSafeDuplicateError, VoteNoRightRep
from loopchain.blockchain.votes.votes import Votes
from loopchain.crypto.signature import Signer


@pytest.mark.parametrize("version_name", ["v0_3", "v0_4"])
def test_votes_v0_1a_equals_to(version_name: str):
    import importlib
    from loopchain.blockchain import votes

    vote_version = importlib.import_module(f"{votes.__name__}.{version_name}")

    assert v0_1a.BlockVotes == vote_version.BlockVotes
    assert v0_1a.LeaderVotes == vote_version.LeaderVotes


class _TestVotesBase:
    SIGNERS = pytest.SIGNERS
    SIGNER = SIGNERS[0]
    REPS = pytest.REPS
    VOTING_RATIO = 0.67
    BLOCK_HEIGHT = 0
    ROUND = 0

    @pytest.fixture
    def vote(self, override_vote_factory):
        pass

    @pytest.fixture
    def votes(self, override_votes_factory):
        pass

    def test_add_vote(self, vote: Vote, votes: Votes):
        votes.add_vote(vote=vote)

    def test_vote_safe_duplicate_error_is_acceptable_in_add_vote(self, vote: Vote, votes: Votes, mocker):
        votes.verify_vote = mocker.MagicMock(side_effect=VoteSafeDuplicateError)

        votes.add_vote(vote=vote)
        assert votes.verify_vote.called

    def test_verify(self, vote: Vote, votes: Votes):
        votes.add_vote(vote=vote)
        votes.verify()

    def test_verify_raises_if_vote_rep_not_equals_votes_rep(self, vote: Vote, votes: Votes):
        votes.add_vote(vote=vote)
        assert self.REPS[0] != self.REPS[1]
        assert self.REPS[0] == vote.rep == votes.reps[0]

        object.__setattr__(vote, "rep", self.REPS[1])

        with pytest.raises(RuntimeError, match="Incorrect Rep"):
            votes.verify()

    def test_verify_vote(self, vote: Vote, votes: Votes):
        votes.verify_vote(vote=vote)

    def test_verify_vote_with_different_height(self, vote: Vote, votes: Votes):
        object.__setattr__(vote, "block_height", 0)
        object.__setattr__(votes, "block_height", 1)

        with pytest.raises(RuntimeError, match="block_height not match"):
            votes.verify_vote(vote=vote)

    def test_verify_vote_with_different_round(self, vote: Vote, votes: Votes):
        object.__setattr__(vote, "round_", 0)
        object.__setattr__(votes, "round", 1)

        with pytest.raises(RuntimeError, match="Vote round not match"):
            votes.verify_vote(vote=vote)

    def test_verify_vote_with_already_added_vote(self, vote: Vote, votes: Votes):
        votes.add_vote(vote)

        with pytest.raises(VoteSafeDuplicateError):
            votes.verify_vote(vote=vote)

    def test_verify_vote_from_invalid_rep_raises_no_right_rep(self, vote: Vote, votes: Votes):
        signer = Signer.new()
        assert signer != self.SIGNER
        assert signer not in self.SIGNERS

        rep_id: ExternalAddress = ExternalAddress.fromhex(signer.address)
        object.__setattr__(vote, "rep", rep_id)

        hash_ = vote.to_hash(**vote.origin_args())
        signature = Signature(signer.sign_hash(hash_))
        object.__setattr__(vote, "signature", signature)

        with pytest.raises(VoteNoRightRep, match="no right to vote"):
            votes.verify_vote(vote=vote)

    def test_get_summary(self, vote: Vote, votes: Votes):
        assert votes.get_summary()

        votes.add_vote(vote)
        assert votes.get_summary()


class _TestBlockVotes(_TestVotesBase):
    block_version = None
    BLOCK_HASH = Hash32(os.urandom(Hash32.size))
    VOTING_RATIO = 0.67
    VOTED_REP_COUNT = int(VOTING_RATIO * 100)

    @pytest.fixture
    def vote(self, block_vote_factory):
        return block_vote_factory(
            block_version=self.block_version,
            signer=self.SIGNER,
            block_hash=self.BLOCK_HASH
        )

    @pytest.fixture
    def votes(self, block_votes_factory):
        return block_votes_factory(
            block_version=self.block_version,
            reps=self.REPS,
            block_hash=self.BLOCK_HASH
        )

    @pytest.fixture
    def setup_votes_for_get_result(self, block_vote_factory, votes):
        def _(voted_rep_count: int, _block_vote_factory, _votes) -> Votes:
            for voter_num in range(voted_rep_count):
                block_vote: v0_1a.BlockVote = block_vote_factory(
                    block_version=self.block_version,
                    signer=self.SIGNERS[voter_num],
                    block_hash=self.BLOCK_HASH)
                votes.add_vote(block_vote)

            return votes

        return functools.partial(_, _block_vote_factory=block_vote_factory, _votes=votes)

    def test_get_result_returns_none_if_not_enough_votes(self, setup_votes_for_get_result):
        votes = setup_votes_for_get_result(self.VOTED_REP_COUNT - 1)

        assert votes.get_result() is None
        assert votes.is_completed() is False

    def test_get_result_returns_none_if_votes_enough_but_result_is_not(self, setup_votes_for_get_result, block_vote_factory):
        votes = setup_votes_for_get_result(self.VOTED_REP_COUNT - 1)

        block_vote: v0_1a.BlockVote = block_vote_factory(
            block_version=self.block_version,
            signer=self.SIGNERS[self.VOTED_REP_COUNT],
            block_hash=Hash32.empty()
        )
        votes.add_vote(block_vote)

        assert votes.get_result() is None
        assert votes.is_completed() is False

    def test_get_result_is_true_if_true_votes_ge_quorum(self, setup_votes_for_get_result):
        votes = setup_votes_for_get_result(self.VOTED_REP_COUNT)

        assert votes.get_result() is True
        assert votes.is_completed() is True

    def test_get_result_is_true_if_false_votes_ge_minimum_true_quorum(self, block_vote_factory, votes):
        failure_threshold_count = 100 - self.VOTED_REP_COUNT

        for voter_num in range(failure_threshold_count):
            block_vote: v0_1a.BlockVote = block_vote_factory(
                block_version=self.block_version,
                signer=self.SIGNERS[voter_num],
                block_hash=Hash32.empty()
            )
            votes.add_vote(block_vote)

        assert votes.get_result() is None
        assert votes.is_completed() is False

        block_vote: v0_1a.BlockVote = block_vote_factory(
            block_version=self.block_version,
            signer=self.SIGNERS[failure_threshold_count],
            block_hash=self.BLOCK_HASH
        )
        votes.add_vote(block_vote)

        assert votes.get_result() is None
        assert votes.is_completed() is False

        block_vote: v0_1a.BlockVote = block_vote_factory(
            block_version=self.block_version,
            signer=self.SIGNERS[failure_threshold_count+1],
            block_hash=Hash32.empty()
        )
        votes.add_vote(block_vote)

        assert votes.get_result() is False
        assert votes.is_completed() is True

    def test_verify_vote_already_added_but_changed_vote_raises_duplicate_err(self, block_vote_factory, votes):
        block_vote: v0_1a.BlockVote = block_vote_factory(block_version=self.block_version, signer=self.SIGNER, block_hash=self.BLOCK_HASH)
        votes.add_vote(block_vote)

        duplicated_vote = block_vote_factory(block_version=self.block_version, signer=self.SIGNER, block_hash=Hash32.empty())

        with pytest.raises(VoteDuplicateError, match="Duplicate voting"):
            votes.verify_vote(vote=duplicated_vote)

    def test_verify_vote_with_different_block_hash(self, vote, votes):
        vote_block_hash = Hash32(os.urandom(Hash32.size))
        assert not vote.block_hash == vote_block_hash

        object.__setattr__(vote, "block_hash", vote_block_hash)

        with pytest.raises(RuntimeError, match="Vote block_hash not match"):
            votes.verify_vote(vote)

    @pytest.fixture
    def setup_votes_for_test_get_majority(self, block_vote_factory, votes: Votes) -> Callable[..., Votes]:
        def _setup_votes_for_test_get_majority(voted_rep_count: int, _block_vote_factory, _votes: Votes) -> Votes:
            # Make up votes
            for voter_num in range(voted_rep_count):
                block_vote: v0_1a.BlockVote = block_vote_factory(block_version=self.block_version, signer=self.SIGNERS[voter_num], block_hash=self.BLOCK_HASH)
                votes.add_vote(block_vote)

            # Make down votes
            for voter_num in range(voted_rep_count, len(self.REPS)):
                block_vote: v0_1a.BlockVote = block_vote_factory(block_version=self.block_version, signer=self.SIGNERS[voter_num], block_hash=Hash32.empty())
                votes.add_vote(block_vote)

            return votes
        return functools.partial(_setup_votes_for_test_get_majority, _block_vote_factory=block_vote_factory, _votes=votes)

    def test_get_majority_most(self, setup_votes_for_test_get_majority):
        voted_rep_count = 66
        votes = setup_votes_for_test_get_majority(voted_rep_count)

        majority_list = votes.get_majority()
        highest_agreement_for_block, highest_voted_count = majority_list[0]

        assert highest_agreement_for_block is True
        assert highest_voted_count == voted_rep_count

    def test_get_majorty_second(self, setup_votes_for_test_get_majority):
        voted_rep_count = 66
        votes = setup_votes_for_test_get_majority(voted_rep_count)

        majority_list = votes.get_majority()
        highest_agreement_for_block, highest_voted_count = majority_list[0]
        second_agreement_for_block, second_voted_count = majority_list[1]

        assert highest_agreement_for_block is True
        assert second_agreement_for_block is False
        assert highest_voted_count == voted_rep_count
        assert second_voted_count == len(self.REPS) - voted_rep_count

    def test_serialize_votes(self, block_vote_factory, votes):
        voted_rep_count = 66
        assert voted_rep_count <= len(self.REPS)

        for voter_num in range(voted_rep_count):
            block_vote: v0_1a.BlockVote = block_vote_factory(block_version=self.block_version, signer=self.SIGNERS[voter_num], block_hash=self.BLOCK_HASH)
            votes.add_vote(block_vote)

        serialized_votes: List[dict] = v0_1a.BlockVotes.serialize_votes(votes=votes.votes)

        vote_num = [serialized_vote for serialized_vote in serialized_votes if serialized_vote]
        assert len(vote_num) == voted_rep_count

    def test_deserialize_votes(self, block_vote_factory, votes):
        voted_rep_count = 66
        assert voted_rep_count <= len(self.REPS)

        for voter_num in range(voted_rep_count):
            block_vote = block_vote_factory(block_version=self.block_version, signer=self.SIGNERS[voter_num], block_hash=self.BLOCK_HASH)
            votes.add_vote(block_vote)

        serialized_votes: List[dict] = votes.serialize_votes(votes=votes.votes)
        deserialized_votes = votes.deserialize_votes(votes_data=serialized_votes)

        assert votes.votes == deserialized_votes

        restored_votes = votes.__class__(
            reps=self.REPS, voting_ratio=self.VOTING_RATIO, block_height=self.BLOCK_HEIGHT, round_=self.ROUND,
            block_hash=self.BLOCK_HASH, votes=votes.votes
        )
        assert votes == restored_votes


class _TestLeaderVotes(_TestVotesBase):
    block_version = None
    OLD_LEADER = pytest.REPS[1]
    NEW_LEADER = pytest.REPS[2]
    VOTING_RATIO = 0.51
    VOTED_REP_COUNT = int(VOTING_RATIO * 100)

    @pytest.fixture
    def vote(self, leader_vote_factory):
        return leader_vote_factory(
            block_version=self.block_version, signer=self.SIGNER, old_leader=self.OLD_LEADER, new_leader=self.NEW_LEADER
        )

    @pytest.fixture
    def votes(self, leader_votes_factory):
        return leader_votes_factory(
            block_version=self.block_version,
            reps=self.REPS,
            old_leader=self.OLD_LEADER,
            block_height=self.BLOCK_HEIGHT,
            round_=self.ROUND
        )

    @pytest.fixture
    def setup_votes_for_get_result(self, leader_vote_factory, votes) -> Callable[..., Votes]:
        def _(voted_rep_count: int, _leader_vote_factory, _votes) -> Votes:
            for voter_num in range(voted_rep_count):
                leader_vote: v0_1a.LeaderVote = leader_vote_factory(
                    block_version=self.block_version,
                    signer=self.SIGNERS[voter_num],
                    old_leader=self.OLD_LEADER,
                    new_leader=self.NEW_LEADER
                )
                votes.add_vote(leader_vote)
            return votes

        return functools.partial(_, _leader_vote_factory=leader_vote_factory, _votes=votes)

    def test_get_result_returns_none_if_not_enough_votes(self, setup_votes_for_get_result):
        votes = setup_votes_for_get_result(self.VOTED_REP_COUNT - 1)

        assert votes.get_result() is None
        assert votes.is_completed() is False

    def test_get_result_returns_new_leader_if_votes_enough(self, setup_votes_for_get_result):
        votes = setup_votes_for_get_result(self.VOTED_REP_COUNT)

        assert votes.get_result() is self.NEW_LEADER
        assert votes.is_completed() is True

    def test_get_result_returns_none_if_votes_enough_but_result_is_not(self, setup_votes_for_get_result, leader_vote_factory):
        votes = setup_votes_for_get_result(self.VOTED_REP_COUNT - 1)

        leader_vote: v0_1a.LeaderVote = leader_vote_factory(
            block_version=self.block_version,
            signer=self.SIGNERS[self.VOTED_REP_COUNT],
            old_leader=self.OLD_LEADER,
            new_leader=self.OLD_LEADER
        )
        votes.add_vote(leader_vote)

        assert votes.get_result() is None
        assert votes.is_completed() is False

    def test_get_result_counts_empty_vote_as_majority(self, setup_votes_for_get_result, leader_vote_factory):
        votes = setup_votes_for_get_result(self.VOTED_REP_COUNT - 1)

        leader_vote: v0_1a.LeaderVote = leader_vote_factory(
            block_version=self.block_version,
            signer=self.SIGNERS[self.VOTED_REP_COUNT],
            old_leader=self.OLD_LEADER,
            new_leader=ExternalAddress.empty()
        )
        votes.add_vote(leader_vote)

        assert votes.get_result() is self.NEW_LEADER
        assert votes.is_completed() is True

    def test_verify_vote_already_added_but_changed_vote_raises_duplicate_err(self, leader_vote_factory, votes):
        leader_vote: v0_1a.LeaderVote = leader_vote_factory(block_version=self.block_version, signer=self.SIGNER, old_leader=self.OLD_LEADER, new_leader=self.NEW_LEADER)
        votes.add_vote(leader_vote)

        duplicated_vote: v0_1a.LeaderVote = leader_vote_factory(block_version=self.block_version, signer=self.SIGNER, old_leader=self.OLD_LEADER, new_leader=self.OLD_LEADER)

        with pytest.raises(VoteDuplicateError, match="Duplicate voting"):
            votes.verify_vote(vote=duplicated_vote)

    def test_verify_vote_with_different_old_leader(self, vote, votes):
        assert not vote.old_leader == self.NEW_LEADER

        object.__setattr__(vote, "old_leader", self.NEW_LEADER)

        with pytest.raises(RuntimeError, match="Vote old_leader not match"):
            votes.verify_vote(vote=vote)

    @pytest.fixture
    def setup_votes_for_test_get_majority(self, leader_vote_factory, votes) -> Callable[..., Votes]:
        def _setup_votes_for_test_get_majority(voted_rep_count: int, _leader_vote_factory, _votes, second_leader=self.REPS[-1]) -> Votes:
            # Make up votes for NEW_LEADER
            for voter_num in range(voted_rep_count):
                leader_vote: v0_1a.LeaderVote = leader_vote_factory(
                    block_version=self.block_version,
                    signer=self.SIGNERS[voter_num],
                    old_leader=self.OLD_LEADER,
                    new_leader=self.NEW_LEADER
                )
                votes.add_vote(leader_vote)

            # Make up votes for second leader
            assert second_leader != self.NEW_LEADER

            for voter_num in range(voted_rep_count, len(self.REPS)):
                leader_vote: v0_1a.LeaderVote = leader_vote_factory(
                    block_version=self.block_version,
                    signer=self.SIGNERS[voter_num],
                    old_leader=self.OLD_LEADER,
                    new_leader=second_leader
                )
                votes.add_vote(leader_vote)

            return votes

        return functools.partial(
            _setup_votes_for_test_get_majority, _leader_vote_factory=leader_vote_factory, _votes=votes
        )

    def test_get_majority_most(self, setup_votes_for_test_get_majority):
        votes = setup_votes_for_test_get_majority(self.VOTED_REP_COUNT)
        majority_list = votes.get_majority()
        highest_voted_leader, highest_voted_count = majority_list[0]

        assert highest_voted_leader is self.NEW_LEADER
        assert highest_voted_count == self.VOTED_REP_COUNT

    def test_get_majority_second(self, setup_votes_for_test_get_majority):
        second_leader = self.REPS[-1]
        votes = setup_votes_for_test_get_majority(self.VOTED_REP_COUNT, second_leader=second_leader)
        majority_list = votes.get_majority()
        second_voted_leader, second_voted_count = majority_list[1]

        assert second_voted_leader == second_leader
        assert second_voted_count == len(self.REPS) - self.VOTED_REP_COUNT

    def test_serialize_votes(self, leader_vote_factory, votes):
        for voter_num in range(self.VOTED_REP_COUNT):
            leader_vote: v0_1a.LeaderVote = leader_vote_factory(
                block_version=self.block_version,
                signer=self.SIGNERS[voter_num],
                old_leader=self.OLD_LEADER,
                new_leader=self.NEW_LEADER
            )
            votes.add_vote(leader_vote)

        serialized_votes: List[dict] = v0_1a.LeaderVotes.serialize_votes(votes=votes.votes)
        vote_num = [serialized_vote for serialized_vote in serialized_votes if serialized_vote]

        assert len(vote_num) == self.VOTED_REP_COUNT

    @pytest.mark.xfail(reason="What is this method for?")
    def test_deserialize(self, leader_vote_factory, votes):
        for voter_num in range(len(self.REPS)):
            leader_vote: v0_1a.LeaderVote = leader_vote_factory(
                block_version=self.block_version,
                signer=self.SIGNERS[voter_num],
                old_leader=self.OLD_LEADER,
                new_leader=self.NEW_LEADER
            )
            votes.add_vote(leader_vote)

        serialized_votes: List[dict] = votes.serialize_votes(votes=votes.votes)
        deserialized_votes = votes.deserialize(votes_data=serialized_votes, voting_ratio=votes.voting_ratio)

        assert votes == deserialized_votes

    @pytest.mark.xfail(reason="What is this method for?")
    def test_deserialize_without_votes(self, votes):
        serialized_votes: List[dict] = votes.serialize_votes(votes=votes.votes)
        assert not all(serialized_votes)
        assert len(serialized_votes) == len(self.REPS)

        deserialized_votes = votes.deserialize(votes_data=serialized_votes, voting_ratio=votes.voting_ratio)

        assert votes == deserialized_votes

    def test_deserialize_votes(self, leader_vote_factory, votes):
        voted_rep_count = 51
        assert voted_rep_count <= len(self.REPS)

        for voter_num in range(voted_rep_count):
            leader_vote = leader_vote_factory(
                block_version=self.block_version,
                signer=self.SIGNERS[voter_num],
                old_leader=self.OLD_LEADER,
                new_leader=self.NEW_LEADER
            )
            votes.add_vote(leader_vote)

        serialized_votes: List[dict] = votes.serialize_votes(votes=votes.votes)
        deserialized_votes = votes.deserialize_votes(votes_data=serialized_votes)

        assert votes.votes == deserialized_votes

        restored_votes = votes.__class__(
            reps=self.REPS, voting_ratio=self.VOTING_RATIO, block_height=self.BLOCK_HEIGHT, round_=self.ROUND,
            old_leader=self.OLD_LEADER, votes=votes.votes
        )

        assert votes == restored_votes
