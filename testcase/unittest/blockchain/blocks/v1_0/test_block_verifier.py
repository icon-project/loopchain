import datetime
import os
from collections import OrderedDict
from typing import Callable, cast
from unittest.mock import MagicMock

import pytest
from freezegun import freeze_time

from loopchain.blockchain import TransactionOutOfTimeBound, BlockVersionNotMatch
from loopchain.blockchain.blocks.v1_0 import Block, BlockVerifier
from loopchain.blockchain.invoke_result import InvokePool, InvokeData
from loopchain.blockchain.transactions import TransactionVersioner
from loopchain.blockchain.transactions import v3
from loopchain.blockchain.types import Hash32, ExternalAddress
from loopchain.crypto.signature import Signer

epoch_num = 1
round_num = 1
height = 1
timestamp = 1

validators_count = 4
signers = [Signer.from_prikey(os.urandom(32)) for _ in range(validators_count)]
validators = [ExternalAddress.fromhex_address(signer.address) for signer in signers]
next_validators_origin = {
    "nextReps": [
        {'id': validator.hex_hx(), 'p2pEndpoint': f'127.0.0.1:{i}'} for i, validator in enumerate(validators)
    ],
    "irep": "0x1",
    "state": "0x0"
}
validators_hash = Hash32(os.urandom(Hash32.size))
next_validators_hash = Hash32.new()  # Validators not changed
state_hash = Hash32(os.urandom(Hash32.size))

pprev_block_hash = Hash32.fromhex("0x9999999999999999999999999999999999999999999999999999999999999999")
prev_block_hash = Hash32.fromhex("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")


@pytest.fixture
def invoke_pool():
    def _invoke(block, tx_versioner):
        invoke_data = InvokeData(
            epoch_num=epoch_num,
            round_num=round_num,
            height=block.header.height,
            receipts=[],
            validators_hash=block.header.validators_hash,
            state_root_hash=state_hash,
            next_validators_origin=next_validators_origin
        )
        return invoke_data

    invoke_pool = MagicMock(InvokePool)()
    invoke_pool.invoke = _invoke
    return cast(InvokePool, invoke_pool)


@pytest.fixture
def block_verifier(invoke_pool):
    tx_versioner = TransactionVersioner()

    return BlockVerifier(tx_versioner, invoke_pool, lambda x: x)


@pytest.fixture
def create_block() -> Callable[..., Block]:
    """Create **Prev** Block as default."""

    def _create_from_kwargs(**kwargs):
        block = MagicMock(Block)

        header = block.header
        header.version = kwargs.get("version", "1.0")
        header.timestamp = kwargs.get("timestamp", 1)
        header.height = kwargs.get("height", 2)
        header.peer_id = kwargs.get("peer_id", validators[header.height % validators_count])
        header.prev_hash = kwargs.get("prev_hash", pprev_block_hash)
        header.hash = kwargs.get("hash", prev_block_hash)
        header.signature = kwargs.get("signature", signers[header.height % validators_count].sign_hash(header.hash))
        header.validators_hash = kwargs.get("validator_hash", validators_hash)
        header.next_validators_hash = kwargs.get("next_validators_hash", Hash32.empty())

        body = block.body
        body.transactions = kwargs.get("transactions", {})

        return cast(Block, block)

    def _create_from_block(prev_block: Block, **kwargs):
        block = MagicMock(Block)

        header = block.header
        header.version = kwargs.get("version", prev_block.header.version)
        header.timestamp = kwargs.get("timestamp", prev_block.header.timestamp + 2000)  # created after 2 sec
        header.height = kwargs.get("height", prev_block.header.height + 1)
        header.peer_id = kwargs.get("peer_id", validators[header.height % validators_count])
        header.prev_hash = kwargs.get("prev_hash", prev_block.header.hash)
        header.hash = kwargs.get("hash", prev_block.header.hash)
        header.signature = kwargs.get("signature", signers[header.height % validators_count].sign_hash(header.hash))
        header.validators_hash = kwargs.get("validator_hash", prev_block.header.revealed_next_reps_hash)
        header.next_validators_hash = kwargs.get("next_validators_hash", Hash32.empty())
        header.transactions_hash = kwargs.get("transactions_hash", Hash32.empty())

        body = block.body
        body.transactions = kwargs.get("transactions", {})

        return cast(Block, block)

    def _(prev_block=None, **kwargs):
        if not prev_block:
            return _create_from_kwargs(**kwargs)
        return _create_from_block(prev_block, **kwargs)

    return _


class _TestVerifierBase:
    @property
    def target_method(self) -> str:
        """Will be mocked all methods except this one.

        :return: "_verify_something"
        """
        raise NotImplementedError

    @pytest.fixture
    def block_verifier(self, block_verifier, monkeypatch):
        for method in dir(block_verifier):
            if "_verify_" in method and self.target_method != method:
                monkeypatch.setattr(block_verifier, method, MagicMock())

        return block_verifier


@pytest.mark.asyncio
class TestVerifyVersion(_TestVerifierBase):
    @property
    def target_method(self):
        return "_verify_version"

    async def test_block_version_dismatched(self, block_verifier, create_block):
        # GIVEN I have blocks
        prev_block = create_block()

        # AND its version is not matched to verifier
        block = create_block(prev_block=prev_block, version="0.5")
        assert block_verifier.version != block.header.version

        # WHEN I verify the block
        with pytest.raises(BlockVersionNotMatch):
            # THEN verification failed
            await block_verifier.verify(prev_block, block)


@pytest.mark.asyncio
class TestVerifyCommon(_TestVerifierBase):
    @property
    def target_method(self):
        return "_verify_common"

    async def test_block_timestamp_not_exist(self, block_verifier, create_block):
        # GIVEN I have blocks
        prev_block = create_block()

        # AND its timestamp is not set
        block = create_block(prev_block, timestamp=None)
        assert block.header.timestamp is None

        # WHEN I verify the block
        with pytest.raises(RuntimeError, match="Block.* timestamp."):
            # THEN verification failed
            await block_verifier.verify(prev_block, block)

    async def test_not_genesis_block_has_no_prev_hash(self, block_verifier, create_block):
        # GIVEN I have blocks
        prev_block = create_block()

        # AND it is not genesis block
        block = create_block(prev_block, height=1, prev_hash=None)
        assert block.header.height != 0
        # AND its prev_hash is not set
        assert block.header.prev_hash is None

        # WHEN I verify the block
        with pytest.raises(RuntimeError, match="Block.* prev_hash."):
            # THEN verification failed
            await block_verifier.verify(prev_block, block)

    async def test_block_prev_hash_not_exist(self, block_verifier, create_block):
        # GIVEN I have blocks
        prev_block = create_block()

        # AND it is not genesis block
        block = create_block(prev_block, height=2, prev_hash=None)
        assert block.header.height != 0
        # AND its prev_hash is not set
        assert block.header.prev_hash is None

        # WHEN I verify the block
        with pytest.raises(RuntimeError, match="Block.* prev_hash."):
            # THEN verification failed
            await block_verifier.verify(prev_block, block)

    @pytest.mark.xfail(reason="Validate reps on BlockVerifier or in Epoch?")
    async def test_reps(self, block_verifier, create_block):
        assert 0

    @pytest.mark.xfail(reason="What should be tested on verify_prev_votes?")
    async def test__verify_prev_votes(self, block_verifier, create_block):
        assert 0


@pytest.mark.asyncio
class TestVerifyTransactions(_TestVerifierBase):
    @property
    def target_method(self):
        return "_verify_transactions"

    @pytest.mark.asyncio
    async def test_tx_time_paradox(self, block_verifier, create_block, tx_factory):
        prev_block: Block = create_block()

        # GIVEN I have txs and they came from far future
        with freeze_time(datetime.datetime.utcnow() + datetime.timedelta(days=5)):
            transactions = OrderedDict()
            for _ in range(5):
                tx = tx_factory(v3.version)
                transactions[tx.hash] = tx
        block: Block = create_block(prev_block, transactions=transactions)

        # THEN Verification fails
        with pytest.raises(TransactionOutOfTimeBound):
            await block_verifier.verify(prev_block, block)


@pytest.mark.asyncio
class TestVerifyBlock:
    async def test_verify(self, block_verifier, create_block):
        prev_block = create_block()
        block = create_block(prev_block)
        await block_verifier.verify(prev_block, block)
