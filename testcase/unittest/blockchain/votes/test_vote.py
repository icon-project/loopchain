import os

import pytest

from loopchain.blockchain.types import ExternalAddress
from loopchain.blockchain.types import Hash32
from loopchain.blockchain.votes import v0_1a, v0_5
from loopchain.blockchain.votes.vote import Vote
from loopchain.crypto.signature import SignVerifier


@pytest.mark.parametrize("version_name", ["v0_3", "v0_4"])
def test_vote_v0_1a_equals_to(version_name: str):
    import importlib
    from loopchain.blockchain import votes

    vote_version = importlib.import_module(f"{votes.__name__}.{version_name}")

    assert v0_1a.BlockVote == vote_version.BlockVote
    assert v0_1a.LeaderVote == vote_version.LeaderVote


class _TestVoteBase:
    SIGNERS = pytest.SIGNERS
    SIGNER = pytest.SIGNERS[0]
    REPS = pytest.REPS

    @pytest.fixture
    def vote(self, override_vote_factory) -> Vote:
        pass

    def test_origin_args_has_valid_form(self, vote: Vote):
        assert "signature" in dir(vote)

        args = vote.origin_args()
        assert isinstance(args, dict)
        assert "signature" not in args

    def test_hash_check(self, vote: Vote):
        origin_args = vote.origin_args()
        hashed = vote.to_hash(**origin_args)

        assert vote.hash() == hashed

    def test_verify(self, vote):
        vote.verify()

    def test_sign_verif_failed_during_vote_verify(self, vote, mocker):
        mocker.patch.object(SignVerifier, "verify_hash", side_effect=ValueError("Something happened in verify_hash"))

        with pytest.raises(RuntimeError, match="Invalid vote signature"):
            vote.verify()

    def test_serialize(self, vote):
        origin_data = vote.serialize()

        assert isinstance(origin_data, dict)

    def test_deserialize(self, vote):
        origin_data = vote.serialize()
        new_vote = vote.deserialize(data=origin_data)

        assert new_vote == vote


class _TestBlockVote(_TestVoteBase):
    block_version = None
    REP = pytest.REPS[0]

    @pytest.fixture
    def vote(self, block_vote_factory):
        return block_vote_factory(block_version=self.block_version, signer=self.SIGNER)

    @pytest.mark.parametrize("block_hash, expected_result", [
        (Hash32(os.urandom(Hash32.size)), True),
        (Hash32.empty(), False)
    ])
    def test_block_vote_result_equals_block_hash(self, block_vote_factory, block_hash, expected_result):
        block_vote = block_vote_factory(block_version=self.block_version, signer=self.SIGNER, block_hash=block_hash)

        assert block_vote.result() is expected_result

    @pytest.mark.xfail(reason="Wrong. Check func signature")
    def test_empty_vote(self, vote):
        block_height = 0
        vote = vote.__class__.empty(rep=self.REP, block_height=block_height)

        assert not vote.result()


class _TestLeaderVote(_TestVoteBase):
    block_version = None
    OLD_LEADER = pytest.REPS[1]
    NEW_LEADER = pytest.REPS[2]

    @pytest.fixture
    def vote(self, leader_vote_factory):
        return leader_vote_factory(
            block_version=self.block_version, signer=self.SIGNER, old_leader=self.OLD_LEADER, new_leader=self.NEW_LEADER
        )

    def test_leader_vote_result_equals_next_leader(self, leader_vote_factory):
        vote = leader_vote_factory(
            block_version=self.block_version, signer=self.SIGNER, old_leader=self.OLD_LEADER, new_leader=self.NEW_LEADER
        )

        assert vote.result() == self.NEW_LEADER

    def test_empty_vote_sets_new_leader_as_empty_hash(self, vote):
        rep_num = 0
        block_height = 0
        round_ = 0

        leader_vote = vote.__class__.empty(
            rep=self.REPS[rep_num], block_height=block_height, round_=round_, old_leader=self.REPS[rep_num]
        )
        assert leader_vote.new_leader == ExternalAddress.empty()
        assert leader_vote.result() == ExternalAddress.empty()
