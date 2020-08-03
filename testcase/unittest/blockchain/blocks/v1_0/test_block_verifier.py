import datetime
import os
from collections import OrderedDict
from typing import Callable, cast
from unittest.mock import MagicMock

import pytest
from freezegun import freeze_time
from loopchain.blockchain import TransactionOutOfTimeBound, BlockVersionNotMatch, BlockProverType
from loopchain.blockchain.blocks import Block as SieverBlock
from loopchain.blockchain.blocks.v0_5 import BlockProver
from loopchain.blockchain.blocks.v0_5.block import BlockHeader as BlockHeader_v0_5, BlockBody as BlockBody_v0_5
from loopchain.blockchain.blocks.v1_0 import Block, BlockVerifier
from loopchain.blockchain.invoke_result import InvokePool, InvokeData
from loopchain.blockchain.transactions import TransactionVersioner
from loopchain.blockchain.transactions import v3
from loopchain.blockchain.types import Hash32, ExternalAddress, Signature, BloomFilter
from loopchain.blockchain.votes.v0_5 import BlockVote as SieverBlockVote
from loopchain.blockchain.votes.v1_0 import BlockVoteFactory, BlockVote
from loopchain.crypto.signature import Signer

epoch_num = 1
round_num = 1
height = 1
timestamp = 1

validators_count = 4
signers = [Signer.from_prikey(os.urandom(32)) for _ in range(validators_count)]
validators = [ExternalAddress.fromhex_address(signer.address) for signer in signers]

# figure out validators hash
block_prover = BlockProver((validator.extend() for validator in validators), BlockProverType.Rep)
validators_hash = block_prover.get_proof_root()

next_validators_origin = {
    "nextReps": [
        {'id': validator.hex_hx(), 'p2pEndpoint': f'127.0.0.1:{i}'} for i, validator in enumerate(validators)
    ],
    "irep": "0x1",
    "state": "0x0"
}
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
    def target_method(self) -> list:
        """Will be mocked all methods except this one.

        :return: ["_verify_something", ]
        """
        raise NotImplementedError

    @pytest.fixture
    def block_verifier(self, block_verifier, monkeypatch):
        for method in dir(block_verifier):
            if "_verify_" in method and method not in self.target_method:
                monkeypatch.setattr(block_verifier, method, MagicMock())

        monkeypatch.setattr(block_verifier, "_reps_getter", lambda reps_hash: validators_hash)
        return block_verifier


@pytest.mark.asyncio
class TestVerifyVersion(_TestVerifierBase):
    @property
    def target_method(self):
        return ["_verify_version"]

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
        return ["_verify_common"]

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


@pytest.mark.asyncio
class TestVerifyPrevVotes(_TestVerifierBase):
    @property
    def target_method(self):
        return ["_verify_prev_votes"]

    async def test_verify_prev_votes(self, block_verifier, create_block, invoke_pool):
        # GIVEN Create a block and a previous block of the block.
        prev_block = create_block()
        block = create_block(prev_block)
        signer = signers[prev_block.header.height % validators_count]
        vote_factory: BlockVoteFactory = BlockVoteFactory(
            invoke_result_pool=invoke_pool,
            signer=signer
        )

        # WHEN Create a vote.
        vote: BlockVote = await vote_factory.create_vote(
            data_id=block.header.hash,
            commit_id=prev_block.header.hash,
            epoch_num=epoch_num,
            round_num=round_num
        )

        block.body.prev_votes = [vote]

        # THEN previous_votes are verified in verify().
        await block_verifier.verify(prev_block, block)


@pytest.mark.asyncio
class TestVerifyPrevVotesBySiever(_TestVerifierBase):
    @property
    def target_method(self):
        return ["_verify_prev_votes", "_verify_prev_votes_by_siever"]

    @property
    def success_message(self) -> str:
        return "!!SUCCESS!!"

    @pytest.fixture
    def mocked_verifier(self, block_verifier, monkeypatch):
        def _raise(self_):
            raise RuntimeError(self.success_message)

        monkeypatch.setattr("loopchain.blockchain.votes.v0_5.BlockVotes.get_result", lambda self_: True)
        monkeypatch.setattr("loopchain.blockchain.votes.v0_5.BlockVotes.verify", _raise)
        return block_verifier

    @pytest.fixture
    def header_factory(self):
        def _header(hash_: Hash32 = Hash32.new(),
                    prev_hash: Hash32 = Hash32.new(),
                    height_: int = 0,
                    timestamp_: int = 0,
                    peer_id: ExternalAddress = ExternalAddress.new(),
                    signature: Signature = Signature.new(),
                    next_leader: ExternalAddress = ExternalAddress.new(),
                    logs_bloom: BloomFilter = BloomFilter.new(),
                    transactions_hash: Hash32 = Hash32.new(),
                    state_hash_: Hash32 = Hash32.new(),
                    receipts_hash: Hash32 = Hash32.new(),
                    reps_hash: Hash32 = Hash32.new(),
                    next_reps_hash: Hash32 = Hash32.new(),
                    leader_votes_hash: Hash32 = Hash32.new(),
                    prev_votes_hash: Hash32 = Hash32.new()) -> BlockHeader_v0_5:

            return BlockHeader_v0_5(hash_, prev_hash, height_, timestamp_, peer_id, signature,
                                    next_leader, logs_bloom, transactions_hash,
                                    state_hash_, receipts_hash, reps_hash,
                                    next_reps_hash, leader_votes_hash, prev_votes_hash)

        return _header

    @pytest.fixture
    def body_factory(self):
        def _body(transactions: dict = dict(), leader_votes: list = list(), prev_votes: list = list()):
            return BlockBody_v0_5(transactions=transactions, leader_votes=leader_votes, prev_votes=prev_votes)

        return _body

    @pytest.fixture
    def create_siever_block(self, header_factory, body_factory) -> Callable[..., Block]:
        """Create **Prev** Block by siever as default."""

        def _create_from_kwargs(**kwargs):
            block = MagicMock(SieverBlock)
            height_ = kwargs.get("height", 2)
            hash_ = kwargs.get("hash", prev_block_hash)

            block.header = header_factory(
                height_=height_,
                timestamp_=kwargs.get("timestamp", 1),
                peer_id=kwargs.get("peer_id", validators[height_ % validators_count]),
                prev_hash=kwargs.get("prev_hash", pprev_block_hash),
                hash_=hash_,
                reps_hash=kwargs.get("validator_hash", validators_hash),
                next_leader=kwargs.get("next_leader", Hash32.empty()),
                next_reps_hash=kwargs.get("next_reps_hash", next_validators_hash),
                signature=kwargs.get("signature", signers[height_ % validators_count].sign_hash(hash_))
            )

            block.body = body_factory()

            return cast(SieverBlock, block)

        def _(prev_block=None, **kwargs):
            if not prev_block:
                return _create_from_kwargs(**kwargs)

        return _

    async def test_verify_prev_votes_by_siever(self, mocked_verifier, create_block, create_siever_block):
        # GIVEN Create a block and the previous block of the block.
        prev_block = create_siever_block()
        block = create_block(prev_block)
        signer = signers[prev_block.header.height % validators_count]

        # WHEN Create a vote.
        vote: SieverBlockVote = SieverBlockVote.new(signer, 1, 2, 0, prev_block.header.hash)
        block.body.prev_votes = [vote]

        # THEN Raises exception to print the success message.
        with pytest.raises(RuntimeError, match=self.success_message):
            await mocked_verifier.verify(prev_block, block)


@pytest.mark.asyncio
class TestVerifyTransactions(_TestVerifierBase):
    @property
    def target_method(self):
        return ["_verify_transactions"]

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
