import functools
import os

import pytest

from loopchain import configure as conf
from loopchain import utils
from loopchain.blockchain.blocks import v0_1a, v0_3, Block, BlockBuilder
from loopchain.blockchain.blocks.block_verifier import BlockVerifier
from loopchain.blockchain.exception import BlockVersionNotMatch, NotInReps, ScoreInvokeError, ScoreInvokeResultError
from loopchain.blockchain.transactions import TransactionVersioner, Transaction
from loopchain.blockchain.transactions import genesis, v2, v3, v3_issue
from loopchain.blockchain.types import Hash32, ExternalAddress, BloomFilter
from loopchain.jsonrpc.exception import GenericJsonRpcServerError


tx_versioner = TransactionVersioner()
tx_versions = [genesis.version, v2.version, v3.version, v3_issue.version]


@pytest.fixture
def build_curr_and_prev_block(block_builder_factory):
    def _wrapped(block_version, _block_builder_factory):
        prev_block_builder: BlockBuilder = block_builder_factory(block_version=block_version)
        prev_block: Block = prev_block_builder.build()

        current_block_builder: BlockBuilder = block_builder_factory(block_version=block_version)
        current_block_builder.height = prev_block.header.height + 1
        current_block_builder.prev_hash = prev_block.header.hash

        current_block: Block = current_block_builder.build()

        return current_block, prev_block

    return functools.partial(_wrapped, _block_builder_factory=block_builder_factory)


@pytest.mark.parametrize("block_version", [v0_1a.version, v0_3.version])
class TestBlockVerifierBase:
    def test_verify_call_check(self, block_version, mocker, build_curr_and_prev_block):
        bv = BlockVerifier.new(version=block_version, tx_versioner=tx_versioner)

        bv.verify_transactions = mocker.MagicMock()
        bv.verify_common = mocker.MagicMock()

        current_block, prev_block = build_curr_and_prev_block(block_version=block_version)
        bv.verify(current_block, prev_block)

        assert bv.verify_transactions.called
        assert bv.verify_common.called

    def test_verify_loosely_call_check(self, block_version, mocker, build_curr_and_prev_block):
        bv = BlockVerifier.new(version=block_version, tx_versioner=tx_versioner)

        bv.verify_transactions_loosely = mocker.MagicMock()
        bv.verify_common = mocker.MagicMock()

        current_block, prev_block = build_curr_and_prev_block(block_version=block_version)
        bv.verify_loosely(current_block, prev_block)

        assert bv.verify_transactions_loosely.called
        assert bv.verify_common.called

    def test_version_check(self, block_version):
        bv = BlockVerifier.new(version=block_version, tx_versioner=tx_versioner)

        if block_version == v0_1a.version:
            assert isinstance(bv, v0_1a.BlockVerifier)
        elif block_version == v0_3.version:
            assert isinstance(bv, v0_3.BlockVerifier)

    def test_verify_signature(self, block_version, block_builder_factory):
        bv = BlockVerifier.new(version=block_version, tx_versioner=tx_versioner)
        block_builder: BlockBuilder = block_builder_factory(block_version=block_version)
        block: Block = block_builder.build()

        bv.verify_signature(block)

    @pytest.mark.parametrize("raise_exc", [True, False])
    def test_verifiy_signature_with_wrong_signature(self, block_version, raise_exc, block_builder_factory):
        from loopchain.blockchain.types import Signature
        bv = BlockVerifier.new(version=block_version, tx_versioner=tx_versioner, raise_exceptions=raise_exc)
        block_builder: BlockBuilder = block_builder_factory(block_version=block_version)
        block_builder.signature = Signature(os.urandom(Signature.size))
        block: Block = block_builder.build()

        if raise_exc:
            with pytest.raises(RuntimeError, match="Invalid Signature"):
                bv.verify_signature(block)
        else:
            assert not bv.exceptions
            bv.verify_signature(block)

            with pytest.raises(RuntimeError, match="Invalid Signature"):
                raise bv.exceptions[0]

    def test_verify_version(self, block_version, block_builder_factory):
        bv = BlockVerifier.new(version=block_version, tx_versioner=tx_versioner)
        block_builder: BlockBuilder = block_builder_factory(block_version=block_version)
        block: Block = block_builder.build()

        assert bv.version == block.header.version
        bv.verify_version(block)

    @pytest.mark.parametrize("raise_exc", [True, False])
    def test_verify_version_with_wrong_version(self, block_version, raise_exc, block_builder_factory):
        bv = BlockVerifier.new(version=block_version, tx_versioner=tx_versioner, raise_exceptions=raise_exc)
        block_builder: BlockBuilder = block_builder_factory(block_version=block_version)
        block: Block = block_builder.build()

        wrong_version = "v4444"
        object.__setattr__(block.header, "version", wrong_version)
        assert block.header.version != block_builder.version

        if raise_exc:
            with pytest.raises(BlockVersionNotMatch):
                bv.verify_version(block)
        else:
            assert not bv.exceptions
            bv.verify_version(block)

            with pytest.raises(BlockVersionNotMatch):
                raise bv.exceptions[0]

    @pytest.mark.parametrize("raise_exc", [True, False])
    def test_verify_common_with_no_timestamp(self, block_version, raise_exc, build_curr_and_prev_block):
        bv = BlockVerifier.new(version=block_version, tx_versioner=tx_versioner, raise_exceptions=raise_exc)
        current_block, prev_block = build_curr_and_prev_block(block_version=block_version)

        object.__setattr__(current_block.header, "timestamp", None)

        if raise_exc:
            with pytest.raises(RuntimeError, match="timestamp"):
                bv.verify_common(current_block, prev_block)
        else:
            assert not bv.exceptions
            # Avoid raising rest of exceptions!
            with pytest.raises(Exception):
                bv.verify_common(current_block, prev_block)

            with pytest.raises(RuntimeError, match="timestamp"):
                raise bv.exceptions[0]

    @pytest.mark.parametrize("raise_exc", [True, False])
    def test_verify_common_with_no_prev_hash(self, block_version, raise_exc, build_curr_and_prev_block):
        bv = BlockVerifier.new(version=block_version, tx_versioner=tx_versioner, raise_exceptions=raise_exc)
        current_block, prev_block = build_curr_and_prev_block(block_version=block_version)

        object.__setattr__(current_block.header, "height", 1)
        object.__setattr__(current_block.header, "prev_hash", None)

        if raise_exc:
            with pytest.raises(RuntimeError, match="prev_hash"):
                bv.verify_common(current_block, prev_block)
        else:
            assert not bv.exceptions
            # Avoid raising rest of exceptions!
            with pytest.raises(Exception):
                bv.verify_common(current_block, prev_block)

            with pytest.raises(RuntimeError, match="prev_hash"):
                raise bv.exceptions[0]

    @pytest.mark.parametrize("raise_exc", [True, False])
    def test_verify_prev_block_with_wrong_prev_height(self, block_version, raise_exc, build_curr_and_prev_block):
        bv = BlockVerifier.new(version=block_version, tx_versioner=tx_versioner, raise_exceptions=raise_exc)
        current_block, prev_block = build_curr_and_prev_block(block_version=block_version)

        object.__setattr__(current_block.header, "height", prev_block.header.height + 2)

        if raise_exc:
            with pytest.raises(RuntimeError, match="Height"):
                bv.verify_prev_block(current_block, prev_block)
        else:
            assert not bv.exceptions
            bv.verify_prev_block(current_block, prev_block)

            with pytest.raises(RuntimeError, match="Height"):
                raise bv.exceptions[0]

    @pytest.mark.parametrize("raise_exc", [True, False])
    def test_verify_prev_block_with_invalid_hash(self, block_version, raise_exc, build_curr_and_prev_block):
        bv = BlockVerifier.new(version=block_version, tx_versioner=tx_versioner, raise_exceptions=raise_exc)
        current_block, prev_block = build_curr_and_prev_block(block_version=block_version)

        object.__setattr__(current_block.header, "prev_hash", Hash32.new())

        if raise_exc:
            with pytest.raises(RuntimeError, match="PrevHash"):
                bv.verify_prev_block(current_block, prev_block)
        else:
            assert not bv.exceptions
            bv.verify_prev_block(current_block, prev_block)

            with pytest.raises(RuntimeError, match="PrevHash"):
                raise bv.exceptions[0]

    @pytest.mark.parametrize("raise_exc", [True, False])
    def test_verify_prev_block_with_invalid_timestamp(self, block_version, raise_exc, build_curr_and_prev_block):
        bv = BlockVerifier.new(version=block_version, tx_versioner=tx_versioner, raise_exceptions=raise_exc)
        current_block, prev_block = build_curr_and_prev_block(block_version=block_version)

        time_over = conf.TIMESTAMP_BUFFER_IN_VERIFIER * 2
        object.__setattr__(current_block.header, "timestamp", utils.get_time_stamp() + time_over)
        object.__setattr__(prev_block.header, "timestamp", utils.get_time_stamp())

        if raise_exc:
            with pytest.raises(RuntimeError, match="timestamp"):
                bv.verify_prev_block(current_block, prev_block)
        else:
            assert not bv.exceptions
            bv.verify_prev_block(current_block, prev_block)

            with pytest.raises(RuntimeError, match="timestamp"):
                raise bv.exceptions[0]

    @pytest.mark.xfail(reason="Fails in genesis tx")
    @pytest.mark.parametrize("tx_version", tx_versions)
    @pytest.mark.parametrize("raise_exc", [True, False])
    def test_verify_txs_with_timed_out_tx(self, block_version, tx_version, raise_exc, tx_factory, block_builder_factory):
        bv = BlockVerifier.new(version=block_version, tx_versioner=tx_versioner, raise_exceptions=raise_exc)
        tx: Transaction = tx_factory(tx_version=tx_version)

        block_builder: BlockBuilder = block_builder_factory(block_version=block_version)
        block_builder.fixed_timestamp = 1
        block_builder.transactions[tx.hash] = tx

        block: Block = block_builder.build()

        from loopchain.blockchain.exception import TransactionOutOfTimeBound
        if raise_exc:
            with pytest.raises(TransactionOutOfTimeBound):
                bv.verify_transactions(block)
        else:
            assert not bv.exceptions
            bv.verify_transactions(block)

            with pytest.raises(TransactionOutOfTimeBound):
                raise bv.exceptions[0]


class TestBlockVerifier_v0_1a:
    version = v0_1a.version

    @pytest.fixture
    def bv(self) -> v0_1a.BlockVerifier:
        return BlockVerifier.new(version=self.version, tx_versioner=tx_versioner)

    def test_verify_common(self, build_curr_and_prev_block):
        bv: v0_1a.BlockVerifier = BlockVerifier.new(version=self.version, tx_versioner=tx_versioner)
        current_block, prev_block = build_curr_and_prev_block(block_version=self.version)
        bv._verify_common(current_block, prev_block)

    @pytest.mark.parametrize("raise_exc", [True, False])
    def test_verify_common_with_wrong_merkle_tree_root_hash(self, mocker, raise_exc, build_curr_and_prev_block):
        bv: v0_1a.BlockVerifier = BlockVerifier.new(version=self.version, tx_versioner=tx_versioner, raise_exceptions=raise_exc)
        current_block, prev_block = build_curr_and_prev_block(block_version=v0_1a.version)

        mocker.patch.object(v0_1a.BlockBuilder, "_build_merkle_tree_root_hash", return_value=Hash32(os.urandom(Hash32.size)))
        if raise_exc:
            with pytest.raises(RuntimeError, match="MerkleTreeRootHash"):
                bv._verify_common(current_block, prev_block)
        else:
            assert not bv.exceptions
            bv._verify_common(current_block, prev_block)

            with pytest.raises(RuntimeError, match="MerkleTreeRootHash"):
                raise bv.exceptions[0]

    @pytest.mark.parametrize("raise_exc", [True, False])
    def test_verify_common_with_wrong_build_hash(self, mocker, raise_exc, build_curr_and_prev_block):
        bv: v0_1a.BlockVerifier = BlockVerifier.new(version=self.version, tx_versioner=tx_versioner, raise_exceptions=raise_exc)
        current_block, prev_block = build_curr_and_prev_block(block_version=v0_1a.version)

        mocker.patch.object(v0_1a.BlockBuilder, "_build_hash", return_value=Hash32(os.urandom(Hash32.size)))
        if raise_exc:
            with pytest.raises(RuntimeError, match="Hash"):
                bv._verify_common(current_block, prev_block)
        else:
            bv._verify_common(current_block, prev_block)
            with pytest.raises(RuntimeError, match="Hash"):
                raise bv.exceptions[0]

    @pytest.mark.parametrize("side_effect, expected_exc", [
        (GenericJsonRpcServerError(code=1, message="Failed to invoke a block.", http_status=400), ScoreInvokeError),
        (RuntimeError, RuntimeError),
        (ValueError, ValueError),
    ])
    @pytest.mark.parametrize("raise_exc", [True, False])
    def test_verify_invoke_failed_in_invoke(self, mocker, raise_exc, side_effect, expected_exc, build_curr_and_prev_block):
        bv: v0_1a.BlockVerifier = BlockVerifier.new(version=self.version, tx_versioner=tx_versioner, raise_exceptions=raise_exc)
        current_block, prev_block = build_curr_and_prev_block(block_version=self.version)

        bv.invoke_func = mocker.MagicMock(side_effect=side_effect)

        if raise_exc:
            with pytest.raises(expected_exc):
                bv.verify_invoke("block_builder_placeholder", current_block, prev_block)
        else:
            assert not bv.exceptions
            bv.verify_invoke("block_builder_placeholder", current_block, prev_block)

            with pytest.raises(expected_exc):
                raise bv.exceptions[0]

    @pytest.mark.parametrize("raise_exc", [True, False])
    def test_verify_invoke_with_wrong_commit_state(self, mocker, raise_exc, build_curr_and_prev_block):
        bv: v0_1a.BlockVerifier = BlockVerifier.new(version=self.version, tx_versioner=tx_versioner, raise_exceptions=raise_exc)
        current_block, prev_block = build_curr_and_prev_block(block_version=v0_1a.version)
        object.__setattr__(current_block.header, "commit_state", Hash32(os.urandom(Hash32.size)))

        mock_new_block = prev_block
        mock_invoke_result = ""
        bv.invoke_func = mocker.MagicMock(return_value=(mock_new_block, mock_invoke_result))

        if raise_exc:
            with pytest.raises(ScoreInvokeResultError):
                bv.verify_invoke("block_builder_placeholder", current_block, prev_block)
        else:
            bv.verify_invoke("block_builder_placeholder", current_block, prev_block)
            with pytest.raises(ScoreInvokeResultError):
                raise bv.exceptions[0]

    def test_verify_invoke_passes_if_empty_block(self, mocker, build_curr_and_prev_block):
        bv: v0_1a.BlockVerifier = BlockVerifier.new(version=self.version, tx_versioner=tx_versioner)
        current_block, prev_block = build_curr_and_prev_block(block_version=self.version)
        object.__setattr__(current_block.header, "commit_state", "")
        object.__setattr__(current_block.body, "transactions", [])

        mock_new_block = prev_block
        mock_invoke_result = ""
        bv.invoke_func = mocker.MagicMock(return_value=(mock_new_block, mock_invoke_result))

        bv.verify_invoke("block_builder_placeholder", current_block, prev_block)

    @pytest.mark.parametrize("raise_exc", [True, False])
    def test_verify_prev_block_with_wrong_leader(self, mocker, raise_exc, build_curr_and_prev_block):
        bv: v0_1a.BlockVerifier = BlockVerifier.new(version=self.version, tx_versioner=tx_versioner, raise_exceptions=raise_exc)
        current_block, prev_block = build_curr_and_prev_block(block_version=self.version)
        object.__setattr__(prev_block.header, "next_leader", ExternalAddress(os.urandom(ExternalAddress.size)))

        mocker.patch.object(BlockVerifier, "verify_prev_block")
        if raise_exc:
            with pytest.raises(RuntimeError):
                bv.verify_prev_block(current_block, prev_block)
        else:
            bv.verify_prev_block(current_block, prev_block)
            with pytest.raises(RuntimeError):
                raise bv.exceptions[0]

    @pytest.mark.xfail(reason="Check that v0.1a and v0.3 have duplicated lines in verify_generator...")
    def test_verify_generator(self, block_builder_factory):
        bv: v0_1a.BlockVerifier = BlockVerifier.new(version=self.version, tx_versioner=tx_versioner)
        block_builder: BlockBuilder = block_builder_factory(block_version=self.version)
        block: Block = block_builder.build()

        bv.verify_generator(block, generator=block.header.peer_id)

    @pytest.mark.parametrize("raise_exc", [True, False])
    def test_verify_generator_with_wrong_generator(self, raise_exc, block_builder_factory):
        bv: v0_1a.BlockVerifier = BlockVerifier.new(version=self.version, tx_versioner=tx_versioner, raise_exceptions=raise_exc)
        block_builder: BlockBuilder = block_builder_factory(block_version=self.version)
        block: Block = block_builder.build()

        invalid_generator = ExternalAddress(os.urandom(ExternalAddress.size))
        assert block.header.peer_id != invalid_generator

        if raise_exc:
            with pytest.raises(RuntimeError, match="Generator"):
                bv.verify_generator(block, generator=invalid_generator)
        else:
            assert not bv.exceptions
            bv.verify_generator(block, generator=invalid_generator)
            assert bv.exceptions

            with pytest.raises(RuntimeError, match="Generator"):
                raise bv.exceptions[0]


class TestBlockVerifier_v0_3:
    BLOCK_VERSION = v0_3.version

    def reps_getter(self, reps):
        fake_reps_hash = Hash32(os.urandom(Hash32.size))

        return fake_reps_hash

    def make_invoke_func(self, mock_new_block):
        def invoke_func(block, prev_block):
            # TODO: Check correct invoke_result format
            invoke_result = {tx_hash.hex(): {"receipt": tx_hash.hex()} for tx_hash, tx in mock_new_block.body.transactions.items()}

            return mock_new_block, invoke_result

        return invoke_func

    @pytest.mark.xfail(reason="hash not in hash? Check return type of reps_getter")
    def test_verify_common_with_block_from_not_in_reps(self, raise_exc, build_curr_and_prev_block):
        bv: v0_3.BlockVerifier = BlockVerifier.new(version=self.BLOCK_VERSION, tx_versioner=tx_versioner, raise_exceptions=raise_exc)
        current_block, prev_block = build_curr_and_prev_block(block_version=v0_3.version)

        if raise_exc:
            with pytest.raises(NotInReps):
                bv._verify_common(current_block, prev_block, reps_getter=self.reps_getter)
        else:
            with pytest.raises(Exception):
                bv._verify_common(current_block, prev_block, reps_getter=self.reps_getter)
            with pytest.raises(NotInReps):
                raise bv.exceptions[0]

    def test_verify_invoke(self, block_builder_factory):
        prev_block_builder: BlockBuilder = block_builder_factory(block_version=self.BLOCK_VERSION)
        prev_block: Block = prev_block_builder.build()

        current_block_builder: BlockBuilder = block_builder_factory(block_version=self.BLOCK_VERSION)
        current_block_builder.height = prev_block.header.height + 1
        current_block_builder.prev_hash = prev_block.header.hash

        current_block: Block = current_block_builder.build()

        bv: v0_3.BlockVerifier = BlockVerifier.new(version=self.BLOCK_VERSION, tx_versioner=tx_versioner)
        bv.invoke_func = self.make_invoke_func(mock_new_block=current_block)
        bv.verify_invoke(current_block_builder, current_block, prev_block)

    @pytest.mark.parametrize("raise_exc", [True, False])
    @pytest.mark.parametrize("tx_version", tx_versions)
    def test_verify_invoke_with_diff_state_hash(self, block_builder_factory, tx_factory, tx_version, raise_exc):
        prev_tx: Transaction = tx_factory(tx_version=tx_version)
        prev_block_builder: BlockBuilder = block_builder_factory(block_version=self.BLOCK_VERSION)
        prev_block_builder.transactions[prev_tx.hash] = prev_tx
        prev_block: Block = prev_block_builder.build()

        curr_tx: Transaction = tx_factory(tx_version=tx_version)
        current_block_builder: BlockBuilder = block_builder_factory(block_version=self.BLOCK_VERSION)
        current_block_builder.height = prev_block.header.height + 1
        current_block_builder.prev_hash = prev_block.header.hash
        current_block_builder.transactions[curr_tx.hash] = curr_tx
        current_block: Block = current_block_builder.build()

        fake_state_hash = Hash32(os.urandom(Hash32.size))
        current_block_builder.state_hash = fake_state_hash
        new_block_by_invoke = current_block_builder.build()
        assert current_block.header.state_hash != new_block_by_invoke.header.state_hash

        bv: v0_3.BlockVerifier = BlockVerifier.new(version=self.BLOCK_VERSION, tx_versioner=tx_versioner, raise_exceptions=raise_exc)
        bv.invoke_func = self.make_invoke_func(mock_new_block=new_block_by_invoke)

        if raise_exc:
            with pytest.raises(RuntimeError, match="StateRootHash"):
                bv.verify_invoke(current_block_builder, current_block, prev_block)
        else:
            assert not bv.exceptions
            bv.verify_invoke(current_block_builder, current_block, prev_block)
            with pytest.raises(RuntimeError, match="StateRootHash"):
                raise bv.exceptions[0]

    @pytest.mark.parametrize("raise_exc", [True, False])
    @pytest.mark.parametrize("tx_version", tx_versions)
    def test_verify_invoke_with_diff_next_reps_hash(self, block_builder_factory, tx_factory, tx_version, raise_exc):
        prev_tx: Transaction = tx_factory(tx_version=tx_version)
        prev_block_builder: BlockBuilder = block_builder_factory(block_version=self.BLOCK_VERSION)
        prev_block_builder.transactions[prev_tx.hash] = prev_tx
        prev_block: Block = prev_block_builder.build()

        curr_tx: Transaction = tx_factory(tx_version=tx_version)
        current_block_builder: BlockBuilder = block_builder_factory(block_version=self.BLOCK_VERSION)
        current_block_builder.height = prev_block.header.height + 1
        current_block_builder.prev_hash = prev_block.header.hash
        current_block_builder.transactions[curr_tx.hash] = curr_tx
        current_block_builder.next_reps_hash = Hash32.empty()
        current_block: Block = current_block_builder.build()

        fake_reps_hash = Hash32(os.urandom(Hash32.size))
        current_block_builder.next_reps_hash = fake_reps_hash
        new_block_by_invoke = current_block_builder.build()
        assert current_block.header.next_reps_hash != new_block_by_invoke.header.revealed_next_reps_hash

        bv: v0_3.BlockVerifier = BlockVerifier.new(version=self.BLOCK_VERSION, tx_versioner=tx_versioner, raise_exceptions=raise_exc)
        bv.invoke_func = self.make_invoke_func(mock_new_block=new_block_by_invoke)

        if raise_exc:
            with pytest.raises(RuntimeError, match="NextRepsHash"):
                bv.verify_invoke(current_block_builder, current_block, prev_block)
        else:
            assert not bv.exceptions
            bv.verify_invoke(current_block_builder, current_block, prev_block)
            with pytest.raises(RuntimeError, match="NextRepsHash"):
                raise bv.exceptions[0]

    @pytest.mark.parametrize("raise_exc", [True, False])
    @pytest.mark.parametrize("tx_version", tx_versions)
    def test_verify_invoke_with_diff_build_receipt_hash(self, block_builder_factory, tx_factory, tx_version, raise_exc):
        prev_tx: Transaction = tx_factory(tx_version=tx_version)
        prev_block_builder: BlockBuilder = block_builder_factory(block_version=self.BLOCK_VERSION)
        prev_block_builder.transactions[prev_tx.hash] = prev_tx
        prev_block: Block = prev_block_builder.build()

        curr_tx: Transaction = tx_factory(tx_version=tx_version)
        current_block_builder: v0_3.BlockBuilder = block_builder_factory(block_version=self.BLOCK_VERSION)
        current_block_builder.height = prev_block.header.height + 1
        current_block_builder.prev_hash = prev_block.header.hash
        current_block_builder.transactions[curr_tx.hash] = curr_tx
        current_block: Block = current_block_builder.build()

        bv: v0_3.BlockVerifier = BlockVerifier.new(version=self.BLOCK_VERSION, tx_versioner=tx_versioner, raise_exceptions=raise_exc)
        bv.invoke_func = self.make_invoke_func(mock_new_block=current_block)

        current_block_builder.receipts_hash = Hash32(os.urandom(Hash32.size))
        if raise_exc:
            with pytest.raises(RuntimeError, match="ReceiptRootHash"):
                bv.verify_invoke(current_block_builder, current_block, prev_block)
        else:
            assert not bv.exceptions
            bv.verify_invoke(current_block_builder, current_block, prev_block)
            with pytest.raises(RuntimeError, match="ReceiptRootHash"):
                raise bv.exceptions[0]

    @pytest.mark.parametrize("raise_exc", [True, False])
    @pytest.mark.parametrize("tx_version", tx_versions)
    def test_verify_invoke_with_diff_logs_bloom(self, block_builder_factory, tx_factory, tx_version, raise_exc):
        prev_tx: Transaction = tx_factory(tx_version=tx_version)
        prev_block_builder: BlockBuilder = block_builder_factory(block_version=self.BLOCK_VERSION)
        prev_block_builder.transactions[prev_tx.hash] = prev_tx
        prev_block: Block = prev_block_builder.build()

        curr_tx: Transaction = tx_factory(tx_version=tx_version)
        current_block_builder: v0_3.BlockBuilder = block_builder_factory(block_version=self.BLOCK_VERSION)
        current_block_builder.height = prev_block.header.height + 1
        current_block_builder.prev_hash = prev_block.header.hash
        current_block_builder.transactions[curr_tx.hash] = curr_tx
        current_block: Block = current_block_builder.build()

        bv: v0_3.BlockVerifier = BlockVerifier.new(version=self.BLOCK_VERSION, tx_versioner=tx_versioner, raise_exceptions=raise_exc)
        bv.invoke_func = self.make_invoke_func(mock_new_block=current_block)

        current_block_builder.logs_bloom = BloomFilter(os.urandom(BloomFilter.size))
        if raise_exc:
            with pytest.raises(RuntimeError, match="LogsBloom"):
                bv.verify_invoke(current_block_builder, current_block, prev_block)
        else:
            assert not bv.exceptions
            bv.verify_invoke(current_block_builder, current_block, prev_block)
            with pytest.raises(RuntimeError, match="LogsBloom"):
                raise bv.exceptions[0]

    @pytest.mark.parametrize("tx_version", tx_versions)
    def test_verify_generator(self, block_builder_factory, tx_factory, tx_version):
        prev_tx: Transaction = tx_factory(tx_version=tx_version)
        prev_block_builder: BlockBuilder = block_builder_factory(block_version=self.BLOCK_VERSION)
        prev_block_builder.transactions[prev_tx.hash] = prev_tx
        prev_block: Block = prev_block_builder.build()

        generator = pytest.REPS[0]
        curr_tx: Transaction = tx_factory(tx_version=tx_version)
        current_block_builder: v0_3.BlockBuilder = block_builder_factory(block_version=self.BLOCK_VERSION)
        current_block_builder.peer_id = generator
        current_block_builder.height = prev_block.header.height + 1
        current_block_builder.prev_hash = prev_block.header.hash
        current_block_builder.transactions[curr_tx.hash] = curr_tx
        current_block: Block = current_block_builder.build()

        assert current_block.header.peer_id == generator

        bv: v0_3.BlockVerifier = BlockVerifier.new(version=self.BLOCK_VERSION, tx_versioner=tx_versioner)
        bv.verify_generator(block=current_block, generator=generator)

    @pytest.mark.parametrize("raise_exc", [True, False])
    @pytest.mark.parametrize("tx_version", tx_versions)
    def test_verify_generator_with_diff_generator(self, block_builder_factory, tx_factory, tx_version, raise_exc):
        prev_tx: Transaction = tx_factory(tx_version=tx_version)
        prev_block_builder: BlockBuilder = block_builder_factory(block_version=self.BLOCK_VERSION)
        prev_block_builder.transactions[prev_tx.hash] = prev_tx
        prev_block: Block = prev_block_builder.build()

        curr_tx: Transaction = tx_factory(tx_version=tx_version)
        current_block_builder: v0_3.BlockBuilder = block_builder_factory(block_version=self.BLOCK_VERSION)
        current_block_builder.height = prev_block.header.height + 1
        current_block_builder.prev_hash = prev_block.header.hash
        current_block_builder.transactions[curr_tx.hash] = curr_tx
        current_block: Block = current_block_builder.build()

        generator = pytest.REPS[0]
        assert not current_block.header.complained
        assert current_block.header.peer_id != generator

        bv: v0_3.BlockVerifier = BlockVerifier.new(version=self.BLOCK_VERSION, tx_versioner=tx_versioner, raise_exceptions=raise_exc)
        if raise_exc:
            with pytest.raises(RuntimeError, match="Generator"):
                bv.verify_generator(block=current_block, generator=generator)
        else:
            assert not bv.exceptions
            bv.verify_generator(block=current_block, generator=generator)
            with pytest.raises(RuntimeError, match="Generator"):
                raise bv.exceptions[0]

    @pytest.mark.parametrize("tx_version", tx_versions)
    def test_verify_leader_votes(self, block_builder_factory, tx_factory, tx_version, leader_vote_factory, leader_votes_factory):
        prev_tx: Transaction = tx_factory(tx_version=tx_version)
        prev_block_builder: BlockBuilder = block_builder_factory(block_version=self.BLOCK_VERSION)
        prev_block_builder.transactions[prev_tx.hash] = prev_tx
        prev_block: Block = prev_block_builder.build()

        curr_tx: Transaction = tx_factory(tx_version=tx_version)
        current_block_builder: v0_3.BlockBuilder = block_builder_factory(block_version=self.BLOCK_VERSION)
        current_block_builder.peer_id = pytest.REPS[0]
        current_block_builder.height = prev_block.header.height + 1
        current_block_builder.prev_hash = prev_block.header.hash
        current_block_builder.transactions[curr_tx.hash] = curr_tx

        from loopchain import configure as conf
        leader_complain_ratio = conf.LEADER_COMPLAIN_RATIO
        signers = pytest.SIGNERS
        reps = pytest.REPS
        old_leader = current_block_builder.peer_id
        round_ = 0

        leader_votes = leader_votes_factory(reps=reps, old_leader=old_leader, voting_ratio=leader_complain_ratio, block_height=current_block_builder.height, round_=round_)
        portion = int(leader_complain_ratio * 100)
        for vote_num in range(portion):
            signer = signers[vote_num]
            leader_vote = leader_vote_factory(signer=signer, block_height=current_block_builder.height, round_=round_, old_leader=old_leader, new_leader=ExternalAddress.empty())
            leader_votes.add_vote(leader_vote)

        current_block_builder.leader_votes = leader_votes.votes
        assert leader_votes.get_result() == ExternalAddress.empty()
        assert current_block_builder.leader_votes

        current_block: Block = current_block_builder.build()

        bv: v0_3.BlockVerifier = BlockVerifier.new(version=self.BLOCK_VERSION, tx_versioner=tx_versioner)
        bv.verify_leader_votes(current_block, prev_block, reps=pytest.REPS)

    @pytest.mark.xfail(reason="Can not reach intended line, because test is failed in LeaderVote verification!")
    @pytest.mark.parametrize("raise_exc", [True, False])
    @pytest.mark.parametrize("tx_version", tx_versions)
    def test_verify_leader_votes_from_wrong_height(self, block_builder_factory, tx_factory, tx_version, raise_exc, leader_vote_factory, leader_votes_factory):
        prev_tx: Transaction = tx_factory(tx_version=tx_version)
        prev_block_builder: BlockBuilder = block_builder_factory(block_version=self.BLOCK_VERSION)
        prev_block_builder.transactions[prev_tx.hash] = prev_tx
        prev_block: Block = prev_block_builder.build()

        curr_tx: Transaction = tx_factory(tx_version=tx_version)
        current_block_builder: v0_3.BlockBuilder = block_builder_factory(block_version=self.BLOCK_VERSION)
        current_block_builder.height = prev_block.header.height + 1
        current_block_builder.prev_hash = prev_block.header.hash
        current_block_builder.transactions[curr_tx.hash] = curr_tx

        from loopchain import configure as conf

        leader_complain_ratio = conf.LEADER_COMPLAIN_RATIO
        signers = pytest.SIGNERS
        reps = pytest.REPS
        old_leader = pytest.REPS[0]
        round_ = 0

        leader_votes = leader_votes_factory(reps=reps, old_leader=old_leader, voting_ratio=leader_complain_ratio, block_height=current_block_builder.height, round_=round_)
        portion = int(leader_complain_ratio * 100) - 1
        for vote_num in range(portion):
            signer = signers[vote_num]
            leader_vote = leader_vote_factory(signer=signer, block_height=current_block_builder.height, round_=round_, old_leader=old_leader, new_leader=ExternalAddress.empty())
            leader_votes.add_vote(leader_vote)

        # wrong_height = current_block_builder.height + 1
        current_block_builder.leader_votes = leader_votes.votes
        assert leader_votes.get_result() == ExternalAddress.empty()
        assert current_block_builder.leader_votes

        current_block: Block = current_block_builder.build()
        object.__setattr__(current_block.header, "height", leader_votes.block_height + 1)
        assert current_block.header.height != leader_votes.block_height

        bv: v0_3.BlockVerifier = BlockVerifier.new(version=self.BLOCK_VERSION, tx_versioner=tx_versioner, raise_exceptions=raise_exc)
        if raise_exc:
            with pytest.raises(RuntimeError, match="Height"):
                bv.verify_leader_votes(current_block, prev_block, reps=pytest.REPS)
        else:
            assert not bv.exceptions
            bv.verify_leader_votes(current_block, prev_block, reps=pytest.REPS)
            with pytest.raises(RuntimeError, match="Height"):
                raise bv.exceptions[0]

    @pytest.mark.parametrize("raise_exc", [True, False])
    @pytest.mark.parametrize("tx_version", tx_versions)
    def test_verify_leader_votes_with_diff_leader(self, block_builder_factory, tx_factory, tx_version, raise_exc, leader_vote_factory, leader_votes_factory):
        prev_tx: Transaction = tx_factory(tx_version=tx_version)
        prev_block_builder: BlockBuilder = block_builder_factory(block_version=self.BLOCK_VERSION)
        prev_block_builder.transactions[prev_tx.hash] = prev_tx
        prev_block: Block = prev_block_builder.build()

        curr_tx: Transaction = tx_factory(tx_version=tx_version)
        current_block_builder: v0_3.BlockBuilder = block_builder_factory(block_version=self.BLOCK_VERSION)
        current_block_builder.peer_id = pytest.REPS[0]
        current_block_builder.height = prev_block.header.height + 1
        current_block_builder.prev_hash = prev_block.header.hash
        current_block_builder.transactions[curr_tx.hash] = curr_tx

        from loopchain import configure as conf
        leader_complain_ratio = conf.LEADER_COMPLAIN_RATIO
        signers = pytest.SIGNERS
        reps = pytest.REPS
        old_leader = current_block_builder.peer_id
        new_leader = reps[-1]
        round_ = 0

        leader_votes = leader_votes_factory(reps=reps, old_leader=old_leader, voting_ratio=leader_complain_ratio, block_height=current_block_builder.height, round_=round_)
        portion = int(leader_complain_ratio * 100)
        for vote_num in range(portion):
            signer = signers[vote_num]
            leader_vote = leader_vote_factory(signer=signer, block_height=current_block_builder.height, round_=round_, old_leader=old_leader, new_leader=new_leader)
            leader_votes.add_vote(leader_vote)

        current_block_builder.leader_votes = leader_votes.votes
        assert leader_votes.get_result() != current_block_builder.peer_id
        assert current_block_builder.leader_votes

        current_block: Block = current_block_builder.build()

        bv: v0_3.BlockVerifier = BlockVerifier.new(version=self.BLOCK_VERSION, tx_versioner=tx_versioner, raise_exceptions=raise_exc)
        if raise_exc:
            with pytest.raises(RuntimeError, match="Leader"):
                bv.verify_leader_votes(current_block, prev_block, reps=pytest.REPS)
        else:
            assert not bv.exceptions
            bv.verify_leader_votes(current_block, prev_block, reps=pytest.REPS)
            with pytest.raises(RuntimeError, match="Leader"):
                raise bv.exceptions[0]

    @pytest.mark.parametrize("raise_exc", [True, False])
    @pytest.mark.parametrize("tx_version", tx_versions)
    def test_verify_leader_votes_passes_but_failed_in_votes_verify(self, block_builder_factory, tx_factory, tx_version, raise_exc, leader_vote_factory, leader_votes_factory, mocker):
        prev_tx: Transaction = tx_factory(tx_version=tx_version)
        prev_block_builder: BlockBuilder = block_builder_factory(block_version=self.BLOCK_VERSION)
        prev_block_builder.transactions[prev_tx.hash] = prev_tx
        prev_block: Block = prev_block_builder.build()

        curr_tx: Transaction = tx_factory(tx_version=tx_version)
        current_block_builder: v0_3.BlockBuilder = block_builder_factory(block_version=self.BLOCK_VERSION)
        current_block_builder.peer_id = pytest.REPS[0]
        current_block_builder.height = prev_block.header.height + 1
        current_block_builder.prev_hash = prev_block.header.hash
        current_block_builder.transactions[curr_tx.hash] = curr_tx

        from loopchain import configure as conf
        leader_complain_ratio = conf.LEADER_COMPLAIN_RATIO
        signers = pytest.SIGNERS
        reps = pytest.REPS
        old_leader = current_block_builder.peer_id
        round_ = 0

        leader_votes = leader_votes_factory(reps=reps, old_leader=old_leader, voting_ratio=leader_complain_ratio, block_height=current_block_builder.height, round_=round_)
        portion = int(leader_complain_ratio * 100)
        for vote_num in range(portion):
            signer = signers[vote_num]
            leader_vote = leader_vote_factory(signer=signer, block_height=current_block_builder.height, round_=round_, old_leader=old_leader, new_leader=ExternalAddress.empty())
            leader_votes.add_vote(leader_vote)

        current_block_builder.leader_votes = leader_votes.votes
        assert leader_votes.get_result() == ExternalAddress.empty()
        assert current_block_builder.leader_votes

        current_block: Block = current_block_builder.build()

        bv: v0_3.BlockVerifier = BlockVerifier.new(version=self.BLOCK_VERSION, tx_versioner=tx_versioner, raise_exceptions=raise_exc)

        from loopchain.blockchain.votes.v0_1a.votes import LeaderVotes
        mocker.patch.object(LeaderVotes, "verify", side_effect=ValueError("test!"))

        if raise_exc:
            with pytest.raises(ValueError, match="test!"):
                bv.verify_leader_votes(current_block, prev_block, reps=pytest.REPS)
        else:
            assert not bv.exceptions
            bv.verify_leader_votes(current_block, prev_block, reps=pytest.REPS)
            with pytest.raises(ValueError, match="test!"):
                raise bv.exceptions[0]

    @pytest.mark.parametrize("raise_exc", [True, False])
    @pytest.mark.parametrize("tx_version", tx_versions)
    def test_verify_leader_votes_with_prep_not_changed_but_leader_diffs_between_prev_and_curr_blocks(self, block_builder_factory, tx_factory, tx_version, raise_exc, leader_vote_factory, leader_votes_factory):
        prev_tx: Transaction = tx_factory(tx_version=tx_version)
        prev_block_builder: BlockBuilder = block_builder_factory(block_version=self.BLOCK_VERSION)
        prev_block_builder.transactions[prev_tx.hash] = prev_tx
        prev_block_builder.next_reps_hash = Hash32.empty()
        prev_block: Block = prev_block_builder.build()

        curr_tx: Transaction = tx_factory(tx_version=tx_version)
        current_block_builder: v0_3.BlockBuilder = block_builder_factory(block_version=self.BLOCK_VERSION)
        current_block_builder.height = prev_block.header.height + 1
        current_block_builder.prev_hash = prev_block.header.hash
        current_block_builder.transactions[curr_tx.hash] = curr_tx

        assert not current_block_builder.leader_votes
        assert prev_block.header.next_leader != current_block_builder.peer_id
        assert not prev_block.header.prep_changed

        current_block: Block = current_block_builder.build()

        bv: v0_3.BlockVerifier = BlockVerifier.new(version=self.BLOCK_VERSION, tx_versioner=tx_versioner, raise_exceptions=raise_exc)

        if raise_exc:
            with pytest.raises(RuntimeError, match="LeaderVotes"):
                bv.verify_leader_votes(current_block, prev_block, reps=pytest.REPS)
        else:
            assert not bv.exceptions
            bv.verify_leader_votes(current_block, prev_block, reps=pytest.REPS)
            with pytest.raises(RuntimeError, match="LeaderVotes"):
                raise bv.exceptions[0]

    @pytest.mark.parametrize("tx_version", tx_versions)
    def test_verify_prev_votes(self, block_builder_factory, tx_factory, tx_version, block_vote_factory, block_votes_factory):
        prev_tx: Transaction = tx_factory(tx_version=tx_version)
        prev_block_builder: BlockBuilder = block_builder_factory(block_version=self.BLOCK_VERSION)
        prev_block_builder.transactions[prev_tx.hash] = prev_tx
        prev_block: Block = prev_block_builder.build()

        curr_tx: Transaction = tx_factory(tx_version=tx_version)
        current_block_builder: v0_3.BlockBuilder = block_builder_factory(block_version=self.BLOCK_VERSION)
        current_block_builder.peer_id = pytest.REPS[0]
        current_block_builder.height = prev_block.header.height + 1
        current_block_builder.prev_hash = prev_block.header.hash
        current_block_builder.transactions[curr_tx.hash] = curr_tx

        from loopchain import configure as conf
        voting_ratio = conf.VOTING_RATIO
        signers = pytest.SIGNERS
        reps = pytest.REPS
        round_ = 0

        block_votes = block_votes_factory(reps, block_hash=prev_block.header.hash, ratio=voting_ratio, block_height=prev_block.header.height, round_=round_)
        portion = int(voting_ratio * 100)
        for vote_num in range(portion):
            signer = signers[vote_num]
            block_vote = block_vote_factory(signer, block_hash=prev_block.header.hash, block_height=prev_block.header.height, round_=round_)
            block_votes.add_vote(block_vote)

        current_block_builder.prev_votes = block_votes.votes
        assert current_block_builder.prev_votes

        current_block: Block = current_block_builder.build()

        bv: v0_3.BlockVerifier = BlockVerifier.new(version=self.BLOCK_VERSION, tx_versioner=tx_versioner)
        bv.verify_prev_votes(current_block, prev_reps=reps)

    @pytest.mark.parametrize("raise_exc", [True, False])
    @pytest.mark.parametrize("tx_version", tx_versions)
    def test_verify_prev_votes_has_not_enough_votes(self, block_builder_factory, tx_factory, tx_version, raise_exc, block_vote_factory, block_votes_factory):
        prev_tx: Transaction = tx_factory(tx_version=tx_version)
        prev_block_builder: BlockBuilder = block_builder_factory(block_version=self.BLOCK_VERSION)
        prev_block_builder.transactions[prev_tx.hash] = prev_tx
        prev_block: Block = prev_block_builder.build()

        curr_tx: Transaction = tx_factory(tx_version=tx_version)
        current_block_builder: v0_3.BlockBuilder = block_builder_factory(block_version=self.BLOCK_VERSION)
        current_block_builder.peer_id = pytest.REPS[0]
        current_block_builder.height = prev_block.header.height + 1
        current_block_builder.prev_hash = prev_block.header.hash
        current_block_builder.transactions[curr_tx.hash] = curr_tx

        from loopchain import configure as conf
        voting_ratio = conf.VOTING_RATIO
        signers = pytest.SIGNERS
        reps = pytest.REPS
        round_ = 0

        block_votes = block_votes_factory(reps, block_hash=prev_block.header.hash, ratio=voting_ratio, block_height=prev_block.header.height, round_=round_)
        portion = int(voting_ratio * 100) - 1
        for vote_num in range(portion):
            signer = signers[vote_num]
            block_vote = block_vote_factory(signer, block_hash=prev_block.header.hash, block_height=prev_block.header.height, round_=round_ )
            block_votes.add_vote(block_vote)

        assert block_votes.get_result() is not True

        current_block_builder.prev_votes = block_votes.votes
        assert current_block_builder.prev_votes

        current_block: Block = current_block_builder.build()

        bv: v0_3.BlockVerifier = BlockVerifier.new(version=self.BLOCK_VERSION, tx_versioner=tx_versioner, raise_exceptions=raise_exc)
        if raise_exc:
            with pytest.raises(RuntimeError, match="PrevVotes"):
                bv.verify_prev_votes(current_block, prev_reps=reps)
        else:
            assert not bv.exceptions
            bv.verify_prev_votes(current_block, prev_reps=reps)
            with pytest.raises(RuntimeError, match="PrevVotes"):
                raise bv.exceptions[0]

    @pytest.mark.parametrize("raise_exc", [True, False])
    @pytest.mark.parametrize("tx_version", tx_versions)
    def test_verify_prev_votes_passes_but_failed_in_votes_verify(self, block_builder_factory, tx_factory, tx_version, raise_exc, block_vote_factory, block_votes_factory, mocker):
        prev_tx: Transaction = tx_factory(tx_version=tx_version)
        prev_block_builder: BlockBuilder = block_builder_factory(block_version=self.BLOCK_VERSION)
        prev_block_builder.transactions[prev_tx.hash] = prev_tx
        prev_block: Block = prev_block_builder.build()

        curr_tx: Transaction = tx_factory(tx_version=tx_version)
        current_block_builder: v0_3.BlockBuilder = block_builder_factory(block_version=self.BLOCK_VERSION)
        current_block_builder.peer_id = pytest.REPS[0]
        current_block_builder.height = prev_block.header.height + 1
        current_block_builder.prev_hash = prev_block.header.hash
        current_block_builder.transactions[curr_tx.hash] = curr_tx

        from loopchain import configure as conf
        voting_ratio = conf.VOTING_RATIO
        signers = pytest.SIGNERS
        reps = pytest.REPS
        round_ = 0

        block_votes = block_votes_factory(reps, block_hash=prev_block.header.hash, ratio=voting_ratio, block_height=prev_block.header.height, round_=round_)
        portion = int(voting_ratio * 100)
        for vote_num in range(portion):
            signer = signers[vote_num]
            block_vote = block_vote_factory(signer, block_hash=prev_block.header.hash, block_height=prev_block.header.height, round_=round_ )
            block_votes.add_vote(block_vote)

        assert block_votes.get_result() is True

        current_block_builder.prev_votes = block_votes.votes
        assert current_block_builder.prev_votes

        current_block: Block = current_block_builder.build()

        bv: v0_3.BlockVerifier = BlockVerifier.new(version=self.BLOCK_VERSION, tx_versioner=tx_versioner, raise_exceptions=raise_exc)

        from loopchain.blockchain.votes.v0_1a.votes import BlockVotes
        mocker.patch.object(BlockVotes, "verify", side_effect=ValueError("test!"))
        if raise_exc:
            with pytest.raises(ValueError, match="test!"):
                bv.verify_prev_votes(current_block, prev_reps=reps)
        else:
            assert not bv.exceptions
            bv.verify_prev_votes(current_block, prev_reps=reps)
            with pytest.raises(ValueError, match="test!"):
                raise bv.exceptions[0]


@pytest.mark.xfail(reason="later")
class TestHeavy:
    def test_verify_transactions(self, tx_module, block_module, block_builder_factory, tx_factory):
        block_builder: BlockBuilder = block_builder_factory(block_version=block_module.version)

        tx: Transaction = tx_factory(version=tx_module.version)
        block_builder.transactions[tx.hash] = tx
        block: Block = block_builder.build()

        bv = BlockVerifier.new(version=block_module.version, tx_versioner=tx_versioner)
        bv.verify_transactions(block)
