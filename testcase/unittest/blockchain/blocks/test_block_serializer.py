import os

import pytest

from loopchain.blockchain.blocks import Block
from loopchain.blockchain.blocks import v0_1a, v0_3
from loopchain.blockchain.blocks.block_serializer import BlockSerializer, BlockVersionNotMatch
from loopchain.blockchain.transactions import Transaction, TransactionVersioner
from loopchain.blockchain.transactions import genesis, v2, v3
from loopchain.blockchain.types import Hash32

tx_versioner = TransactionVersioner()
tx_versions = [genesis.version, v2.version, v3.version]


@pytest.mark.parametrize("block_version", [v0_1a.version, v0_3.version])
class TestBlockSerializerBase:
    def test_version_check(self, block_version):
        bs = BlockSerializer.new(version=block_version, tx_versioner=tx_versioner)

        if block_version == v0_1a:
            assert isinstance(bs, v0_1a.BlockSerializer)
        elif block_version == v0_3:
            assert isinstance(bs, v0_3.BlockSerializer)

    def test_deserialize_raises_exc_if_block_has_different_version(self, block_version):
        bs = BlockSerializer.new(version=block_version, tx_versioner=tx_versioner)

        block_dumped = {
            "version": "wrong_version"
        }
        with pytest.raises(BlockVersionNotMatch, match="The block of this version cannot be deserialized"):
            bs.deserialize(block_dumped)


class TestBlockSerializer_v0_1a:
    BLOCK_VERSION = v0_1a.version
    TX_COUNT = 5

    @pytest.fixture
    def bs(self) -> v0_1a.BlockSerializer:
        return BlockSerializer.new(version=self.BLOCK_VERSION, tx_versioner=tx_versioner)

    @pytest.mark.parametrize("tx_version", tx_versions)
    def test_serialize_and_deserialize(self, bs, block_builder_factory, tx_version, tx_factory):
        if tx_version == genesis.version:
            pytest.skip(msg="Tx hash differs.")
        elif tx_version == v2.version:
            pytest.skip(msg="to_address differs.")

        block_builder = block_builder_factory(block_version=self.BLOCK_VERSION)

        for _ in range(self.TX_COUNT):
            tx: Transaction = tx_factory(tx_version=tx_version)
            block_builder.transactions[tx.hash] = tx

        block: Block = block_builder.build()

        block_dumped: dict = bs.serialize(block=block)
        restored_block: Block = bs.deserialize(block_dumped=block_dumped)

        # TODO: Why serialized block has no info about confirm_prev_block?
        object.__setattr__(restored_block.body, "confirm_prev_block", block.body.confirm_prev_block)

        assert block.body.transactions == restored_block.body.transactions
        assert block == restored_block

    def test_serialized_has_valid_form(self, bs, block_builder_factory):
        block_builder: v0_1a.BlockBuilder = block_builder_factory(block_version=self.BLOCK_VERSION)
        block: Block = block_builder.build()

        block_dumped: dict = bs.serialize(block=block)
        keys = [
            "version",
            "prev_block_hash",
            "merkle_tree_root_hash",
            "time_stamp",
            "confirmed_transaction_list",
            "block_hash",
            "height",
            "peer_id",
            "signature",
            "next_leader",
            "commit_state",
        ]

        for block_attr in keys:
            block_dumped.pop(block_attr)

        assert not block_dumped

    def test_serialize_raises_exc_if_block_has_different_version(self, bs, block_builder_factory):
        block_builder = block_builder_factory(block_version=self.BLOCK_VERSION)
        block: Block = block_builder.build()

        bs.version = "wrong_version"
        assert block.header.version != bs.version

        with pytest.raises(BlockVersionNotMatch, match="The block of this version cannot be serialized"):
            bs.serialize(block=block)


class TestBlockSerializer_v0_3:
    BLOCK_VERSION = v0_3.version
    STATE_HASH = Hash32(os.urandom(Hash32.size))
    TX_COUNT = 5

    @pytest.fixture
    def bs(self) -> v0_3.BlockSerializer:
        return BlockSerializer.new(version=self.BLOCK_VERSION, tx_versioner=tx_versioner)

    @pytest.mark.parametrize("tx_version", tx_versions)
    def test_serialize_and_deserialize(self, bs, block_builder_factory, tx_version, tx_factory):
        if tx_version == genesis.version:
            pytest.skip(msg="Tx hash differs.")
        elif tx_version == v2.version:
            pytest.skip(msg="to_address differs.")

        block_builder = block_builder_factory(block_version=self.BLOCK_VERSION)
        block_builder.state_hash = self.STATE_HASH

        for _ in range(self.TX_COUNT):
            tx: Transaction = tx_factory(tx_version=tx_version)
            block_builder.transactions[tx.hash] = tx
        block: Block = block_builder.build()

        block_dumped: dict = bs.serialize(block=block)
        restored_block: Block = bs.deserialize(block_dumped=block_dumped)

        assert block.body.transactions == restored_block.body.transactions
        assert block == restored_block

    def test_serialized_has_valid_form(self, bs, block_builder_factory):
        block_builder: v0_3.BlockBuilder = block_builder_factory(block_version=self.BLOCK_VERSION)
        block_builder.state_hash = self.STATE_HASH
        block: Block = block_builder.build()

        block_dumped: dict = bs.serialize(block=block)
        keys = [
            "version",
            "prevHash",
            "transactionsHash",
            "stateHash",
            "receiptsHash",
            "repsHash",
            "nextRepsHash",
            "leaderVotesHash",
            "prevVotesHash",
            "logsBloom",
            "timestamp",
            "transactions",
            "leaderVotes",
            "prevVotes",
            "hash",
            "height",
            "leader",
            "signature",
            "nextLeader",
        ]

        for block_attr in keys:
            block_dumped.pop(block_attr)

        assert not block_dumped

    def test_serialize_raises_exc_if_block_has_different_version(self, bs, block_builder_factory):
        block_builder = block_builder_factory(block_version=self.BLOCK_VERSION)
        block_builder.state_hash = self.STATE_HASH
        block: Block = block_builder.build()

        bs.version = "wrong_version"
        assert block.header.version != bs.version

        with pytest.raises(BlockVersionNotMatch, match="The block of this version cannot be serialized"):
            bs.serialize(block=block)
