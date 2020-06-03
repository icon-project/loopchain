import pytest

from loopchain import configure_default as conf
from loopchain.blockchain.epoch3 import LoopchainEpoch
from loopchain.blockchain.types import ExternalAddress


class TestEpoch:
    @pytest.mark.parametrize("voter_count", [100, 33, 7])
    def test_voters_num(self, voter_count):
        # WHEN The epoch has number of `voter_count` voters
        voters = [ExternalAddress.new() for _ in range(voter_count)]
        epoch = LoopchainEpoch(num=1, voters=voters)

        # THEN its voters_num should be voter_count
        assert epoch.voters_num == voter_count

    @pytest.mark.parametrize("voter_count, expected_quorum", [(100, 67), (10, 7), (33, 23)])
    def test_quorum_num(self, voter_count, expected_quorum):
        # WHEN The epoch has number of `voter_count` voters
        voters = [ExternalAddress.new() for _ in range(voter_count)]
        epoch = LoopchainEpoch(num=1, voters=voters)

        # THEN its quorum deadline should be expected quorum
        assert epoch.quorum_num == expected_quorum
        # AND quorum must be 0.67
        assert conf.VOTING_RATIO == 0.67

    def test_proposer_rotated_by_round(self):
        # GIVEN There's 22 voters
        total_voters = 22
        voters = [f"node{i}".encode() for i in range(total_voters)]

        # AND Each node has 10 chances to generate block.
        assert conf.MAX_MADE_BLOCK_COUNT == 10
        rotate_bound = conf.MAX_MADE_BLOCK_COUNT
        epoch = LoopchainEpoch(num=0, voters=voters, rotate_bound=rotate_bound)

        # WHEN It comes to first round
        round_num = 0
        # THEN The leader node should be the first node in voters
        assert epoch.get_proposer_id(round_num) == voters[0]

        # WHEN The first node succeeds or fails generating block
        round_num = 1
        # THEN The leader node should be the first one (not changed)
        assert epoch.get_proposer_id(round_num) == voters[0]

        # WHEN The round comes 9
        round_num = 9
        # THEN The leader node should be the first one (not changed)
        assert epoch.get_proposer_id(round_num) == voters[0]

        # WHEN The first node has been spent all its chances
        round_num = 10
        # THEN The leader node should be changed as next one
        assert epoch.get_proposer_id(round_num) == voters[1]

        # WHEN It comes that the last chance of the last node
        round_num = 219
        # THEN The leader node should be the last node
        assert epoch.get_proposer_id(round_num) == voters[-1]

        # WHEN All nodes had been spent all chances
        round_num = 220
        # THEN The leader node should be the first node
        assert epoch.get_proposer_id(round_num) == voters[0]

    def test_compare_epoches(self):
        # GIVEN I have two
        voters0 = [f"node{i}".encode() for i in range(22)]

        # WHEN I have various epochs
        epoch_prime = LoopchainEpoch(num=0, voters=voters0, rotate_bound=10)
        epoch_prime_ = LoopchainEpoch(num=0, voters=voters0, rotate_bound=10)
        epoch_diff_num = LoopchainEpoch(num=1, voters=voters0, rotate_bound=10)
        epoch_diff_voters = LoopchainEpoch(num=0, voters=["node999"], rotate_bound=10)
        epoch_diff_rotate_bound = LoopchainEpoch(num=0, voters=voters0, rotate_bound=9)

        # THEN They must be not same,
        assert epoch_prime != epoch_diff_num
        assert epoch_prime != epoch_diff_voters
        assert epoch_prime != epoch_diff_rotate_bound

        # Except identical epoches
        assert epoch_prime == epoch_prime_
