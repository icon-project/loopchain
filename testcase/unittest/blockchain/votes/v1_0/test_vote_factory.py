import os
from typing import Callable

import pytest

from loopchain.blockchain.invoke_result import InvokeData, InvokePool
from loopchain.blockchain.types import Hash32, ExternalAddress
from loopchain.blockchain.votes.v1_0 import BlockVote, BlockVoteFactory
from loopchain.crypto.signature import Signer


class TestVoteFactory:
    @pytest.fixture
    def invoke_pool(self) -> InvokePool:
        return InvokePool()

    @pytest.fixture
    def mock_verify(self, icon_invoke) -> Callable[[InvokePool, int, int], InvokeData]:
        """Suppose that caller of verifier proceeds invoke."""

        def _(invoke_pool: InvokePool, epoch_num: int, round_num: int):
            invoke_data: InvokeData = InvokeData.new(
                epoch_num=epoch_num,
                round_num=round_num,
                height=1,
                current_validators_hash=Hash32.fromhex("0xea2254afbeaa13c73b6f366bfc7621e2a155df9e3ee1e1e7c00df5345c84a7af"),
                invoke_result=icon_invoke
            )
            invoke_pool.add_message(invoke_data)

            return invoke_data

        return _

    @pytest.mark.asyncio
    async def test_create_vote(self, invoke_pool, mock_verify):
        # GIVEN I have information of previous block
        prev_block_hash = Hash32.fromhex("0xea2254afbeaa13c73b6f366bfc7621e2a155df9e3ee1e1e7c00df5345c84a7af")

        # AND I proved that the current block is valid
        epoch_num = 10
        round_num = 10
        mock_verify(invoke_pool, epoch_num, round_num)

        # AND I prepare to create upvote on the current block
        signer = Signer.new()
        vote_factory: BlockVoteFactory = BlockVoteFactory(
            invoke_result_pool=invoke_pool,
            signer=signer
        )

        # WHEN I create vote
        vote: BlockVote = await vote_factory.create_vote(
            data_id=Hash32.fromhex("0xc71303ef8543d04b5dc1ba6579132b143087c68db1b2168786408fcbce568238"),
            commit_id=prev_block_hash,
            epoch_num=epoch_num,
            round_num=round_num
        )

        # THEN The vote should be valid vote (upvote)
        assert vote.is_real()
        assert not vote.is_none()
        assert not vote.is_lazy()

    @pytest.mark.asyncio
    async def test_lazy_vote(self, invoke_pool):
        # GIVEN I create VoteFactory
        signer = Signer.new()
        vote_factory: BlockVoteFactory = BlockVoteFactory(
            invoke_result_pool=invoke_pool,
            signer=signer
        )

        # WHEN I create none vote
        vote: BlockVote = vote_factory.create_lazy_vote(
            voter_id=ExternalAddress(os.urandom(ExternalAddress.size)),
            epoch_num=1,
            round_num=1
        )

        # THEN The factory should be a none vote
        assert not vote.is_real()
        assert not vote.is_none()
        assert vote.is_lazy()

    @pytest.mark.asyncio
    async def test_none_vote(self, invoke_pool):
        # GIVEN I create VoteFactory
        signer = Signer.new()
        vote_factory: BlockVoteFactory = BlockVoteFactory(
            invoke_result_pool=invoke_pool,
            signer=signer
        )

        # WHEN I create none vote
        vote: BlockVote = vote_factory.create_none_vote(
            epoch_num=1,
            round_num=1
        )

        # THEN The factory should be a none vote
        assert vote.is_real()
        assert vote.is_none()
        assert not vote.is_lazy()
