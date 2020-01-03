from testcase.unittest.blockchain.votes.test_vote import _TestBlockVote


class TestBlockVote(_TestBlockVote):
    block_version = "0.5"

    def test_round_key_is_round(self, vote):
        assert "round_" not in vote.__dataclass_fields__.keys()
        assert "round" in vote.__dataclass_fields__.keys()
