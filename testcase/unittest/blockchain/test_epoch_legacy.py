from typing import Callable, List

import pytest

from loopchain import configure_default as conf
from loopchain.blockchain.epoch import Epoch
from loopchain.blockchain.types import ExternalAddress, Hash32
from loopchain.blockchain.votes.v0_5 import LeaderVote
from loopchain.crypto.signature import Signer


class TestEpoch:
    block_version = "0.5"
    last_block_height = 5

    signers: List[Signer] = pytest.SIGNERS
    reps: List[ExternalAddress] = pytest.REPS
    reps_count = len(reps)

    current_leader = reps[0]
    new_leader = reps[1]

    @pytest.fixture
    def epoch_factory(self) -> Callable[..., Epoch]:
        def _(**kwargs):
            reps_hash = Hash32.new()
            reps = TestEpoch.reps
            last_block_height = kwargs.get("last_block_height", TestEpoch.last_block_height)
            leader_id: str = TestEpoch.current_leader.hex_hx()
            return Epoch(
                reps_hash, reps, TestEpoch.block_version, last_block_height, leader_id
            )
        return _

    @pytest.fixture
    def leader_vote_factory(self) -> Callable[..., LeaderVote]:
        def _(**kwargs):
            signer = kwargs["signer"]
            timestamp = 1
            block_height = kwargs.get("block_height", TestEpoch.last_block_height+1)
            round_ = kwargs.get("round", 0)
            old_leader: ExternalAddress = kwargs.get("old_leader", TestEpoch.current_leader)
            new_leader: ExternalAddress = kwargs.get("new_leader", TestEpoch.new_leader)
            return LeaderVote.new(signer, timestamp, block_height, round_, old_leader, new_leader)
        return _

    @pytest.mark.parametrize("last_block_height", [2, 11, 100])
    def test_epoch_must_have_next_height_of_last_block(self, epoch_factory, last_block_height):
        # WHEN I create epoch AND I have a last block
        epoch: Epoch = epoch_factory(last_block_height=last_block_height)

        # THEN it must have the next height of the last block
        assert epoch.height == last_block_height + 1

    def test_epoch_height_should_be_one_if_height_not_supplied(self, epoch_factory):
        # WHEN I create epoch AND I do not have a last block
        epoch: Epoch = epoch_factory(last_block_height=None)

        # THEN its height should be one
        assert epoch.height == 1

    def test_complain_result(self, epoch_factory, leader_vote_factory):
        # GIVEN I got a leader vote from Node 0
        epoch = epoch_factory()
        leader_vote: LeaderVote = leader_vote_factory(signer=TestEpoch.signers[0])

        # AND his or her complaint is valid
        assert leader_vote.round == epoch.round
        assert leader_vote.block_height == epoch.height

        # WHEN I accept it
        epoch.add_complain(leader_vote)

        # THEN nothing happens
        assert not epoch.complain_result()

        # WHEN 66 nodes complains
        for i in range(1, 66):
            leader_vote: LeaderVote = leader_vote_factory(signer=TestEpoch.signers[i])
            epoch.add_complain(leader_vote)

        # THEN nothing happens
        assert not epoch.complain_result()

        # WHEN another node complains, which makes leader votes to reach its threshold
        leader_vote: LeaderVote = leader_vote_factory(signer=TestEpoch.signers[66])
        epoch.add_complain(leader_vote)

        # THEN complain_result is made
        assert epoch.complain_result()

    def test_ignore_complain_result_from_invalid_height(self, epoch_factory, leader_vote_factory):
        epoch = epoch_factory()

        # WHEN I got leader votes
        for i in range(TestEpoch.reps_count):
            leader_vote: LeaderVote = leader_vote_factory(signer=TestEpoch.signers[i], block_height=3)
            assert leader_vote.round == epoch.round

            # AND they came from another height
            assert leader_vote.block_height != epoch.height

        # THEN complain_result is not made
        assert not epoch.complain_result()

    def test_ignore_complain_result_from_invalid_round(self, epoch_factory, leader_vote_factory):
        epoch = epoch_factory()

        # WHEN I got leader votes
        for i in range(TestEpoch.reps_count):
            leader_vote: LeaderVote = leader_vote_factory(signer=TestEpoch.signers[i], round=8)
            # AND they came from another height
            assert leader_vote.round != epoch.round
            assert leader_vote.block_height == epoch.height

        # THEN complain_result is not made
        assert not epoch.complain_result()
