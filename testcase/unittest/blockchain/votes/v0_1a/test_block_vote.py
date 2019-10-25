from testcase.unittest.blockchain.votes.test_vote import _TestBlockVote


class TestBlockVote(_TestBlockVote):
    block_version = "0.1a"

    def test_round_key_is_round_(self, vote):
        assert "round_" in vote.__dataclass_fields__.keys()
        assert "round" not in vote.__dataclass_fields__.keys()
