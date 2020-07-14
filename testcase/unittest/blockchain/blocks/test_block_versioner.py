import pytest

from loopchain.blockchain.blocks import BlockVersioner


class TestBlockVersioner:
    block_versions = {
        "0.1a": 0,
        "0.4": 10,
        "0.5": 25,
        "1.0": 40
    }

    @pytest.fixture
    def block_versioner(self):
        # GIVEN I have block versioner
        block_versioner = BlockVersioner()

        # AND I initialize it with block version info
        for version, height in TestBlockVersioner.block_versions.items():
            block_versioner.add_version(height, version)

        return block_versioner

    def test_get_version(self, block_versioner):
        start_info: list = sorted(TestBlockVersioner.block_versions.items())
        end_info = start_info[1:]
        last_version, last_height = start_info[-1]
        end_info.append((last_version, last_height+50))  # For last version test

        # WHEN I get version by height...
        for each_start, each_end in zip(start_info, end_info):
            # From certain height of version...
            start_ver, start_height = each_start
            # Until the height whose version is supposed to be changed
            end_ver, end_height = each_end

            # THEN returned version should be start version
            for height in range(start_height, end_height):
                assert start_ver == block_versioner.get_version(height)

    def test_get_start_height(self, block_versioner):
        for version, height in TestBlockVersioner.block_versions.items():
            assert height == block_versioner.get_start_height(version)

    def test_get_start_height_invalid(self, block_versioner):
        # GIVEN I have a block version
        wrong_version = "0.7"
        # AND It is not found in BlockVersioner
        assert wrong_version not in TestBlockVersioner.block_versions.keys()

        # WHEN I try to get height of wrong version
        with pytest.raises(RuntimeError, match=f"no block version. version: {wrong_version}"):
            # THEN Exception raises
            block_versioner.get_start_height(wrong_version)
