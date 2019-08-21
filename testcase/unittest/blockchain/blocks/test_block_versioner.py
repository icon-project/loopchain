import json
import random

import pytest

from loopchain.blockchain.blocks import BlockVersioner
from loopchain.blockchain.blocks import v0_1a
from loopchain.blockchain.blocks import v0_3
from loopchain.blockchain.blocks.block_versioner import BlockVersion
from loopchain.blockchain.types import Hash32


class TestBlockVersioner:
    block_versions = [v0_1a.version, v0_3.version]
    height_from_v0_1a = 0
    height_from_v0_3 = 20

    def test_default_version_init_with_v0_1a(self):
        block_versioner = BlockVersioner()
        default_version = BlockVersion(0, "0.1a")
        assert len(block_versioner._versions) == 1
        assert block_versioner._versions[0] == default_version

    @pytest.mark.parametrize("expected_version_name", block_versions)
    def test_add_version(self, expected_version_name):
        expected_height = 1

        block_versioner = BlockVersioner()
        block_versioner.add_version(height=expected_height, version_name=expected_version_name)

        assert len(block_versioner._versions) == 1
        assert block_versioner._versions[0] == BlockVersion(height=expected_height, name=expected_version_name)

    @pytest.mark.parametrize("expected_version_name", block_versions)
    def test_duplicated_version_added(self, expected_version_name):
        expected_height = 1

        block_versioner = BlockVersioner()
        block_versioner.add_version(height=expected_height, version_name=expected_version_name)

        with pytest.raises(ValueError, match="Duplicated"):
            block_versioner.add_version(height=expected_height, version_name=expected_version_name)

    @pytest.mark.parametrize('run_n_times', range(10))
    def test_multiple_version_added_and_sorted_by_height(self, run_n_times):
        random_heights = random.sample(range(0, 100), len(TestBlockVersioner.block_versions))

        block_versioner = BlockVersioner()
        for expected_height, version_name in zip(random_heights, TestBlockVersioner.block_versions):
            block_versioner.add_version(height=expected_height, version_name=version_name)

        assert len(block_versioner._versions) == len(TestBlockVersioner.block_versions)

        heights_sorted_asc = sorted(random_heights)
        for added_block_version, expected_height in zip(block_versioner._versions, heights_sorted_asc):
            assert added_block_version.height == expected_height

    def test_get_version_returns_version_until_reaches_next_version_height(self):
        block_versioner = BlockVersioner()
        block_versioner.add_version(height=TestBlockVersioner.height_from_v0_1a, version_name=v0_1a.version)
        block_versioner.add_version(height=TestBlockVersioner.height_from_v0_3, version_name=v0_3.version)

        for height_under_v0_3 in range(TestBlockVersioner.height_from_v0_3):
            assert block_versioner.get_version(height_under_v0_3) == v0_1a.version

        assert block_versioner.get_version(TestBlockVersioner.height_from_v0_3) == v0_3.version

    def test_get_version_raises_exc_in_not_added_version_heights(self):
        block_versioner = BlockVersioner()
        block_versioner.add_version(height=TestBlockVersioner.height_from_v0_3, version_name=v0_3.version)

        for not_added_height in range(TestBlockVersioner.height_from_v0_3):
            with pytest.raises(RuntimeError):
                block_versioner.get_version(height=not_added_height)

    @pytest.mark.parametrize("is_dumped_block_test", [True, False])
    @pytest.mark.parametrize("block", [{"height": 1}, {"height": "1"}])
    def test_get_height_with_various_cases(self, block, is_dumped_block_test):
        expected_height = 1
        block_versioner = BlockVersioner()

        if is_dumped_block_test:
            block = json.dumps(block)

        height = block_versioner.get_height(block_dumped=block)
        assert height == expected_height

    @pytest.mark.parametrize("block_hash_key", ["block_hash", "hash"])
    @pytest.mark.parametrize("block_version", [v0_1a.version, v0_3.version])
    def test_get_hash_with_various_cases(self, block_hash_key, block_version):
        # TODO: Dumped block and string hashes not tested!
        block_versioner = BlockVersioner()

        expected_hash = Hash32.new()
        block = {
            block_hash_key: expected_hash,
            "version": block_version
        }

        hash_ = block_versioner.get_hash(block)
        assert hash_ == expected_hash
