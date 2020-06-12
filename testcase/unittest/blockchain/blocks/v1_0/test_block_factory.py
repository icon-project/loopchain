from typing import List

import pytest
from lft.consensus.epoch import EpochPool

from loopchain.baseservice.aging_cache import AgingCache
from loopchain.blockchain import Hash32, ExternalAddress
from loopchain.blockchain.blocks import v1_0
from loopchain.blockchain.invoke_result import InvokePool, InvokeData
from loopchain.blockchain.transactions import TransactionVersioner
from loopchain.blockchain.votes.v1_0 import BlockVote
from loopchain.crypto.signature import Signer
from loopchain.store.key_value_store import KeyValueStore


class TestBlockFactory:
    @pytest.fixture
    def block_factory(self, mocker, icon_preinvoke) -> v1_0.BlockFactory:
        # TODO: Temporary mocking...
        tx_queue: AgingCache = mocker.MagicMock(AgingCache)
        db: KeyValueStore = mocker.MagicMock(KeyValueStore)
        tx_versioner = TransactionVersioner()

        invoke_pool: InvokePool = mocker.MagicMock(InvokePool)
        invoke_pool.prepare_invoke.return_value = InvokeData.from_dict(
            epoch_num=1,
            round_num=1,
            query_result=icon_preinvoke
        )
        signer: Signer = Signer.new()
        epoch_pool = EpochPool()

        return v1_0.BlockFactory(epoch_pool, tx_queue, db, tx_versioner, invoke_pool, signer)

    @pytest.fixture
    def prev_votes(self) -> List[BlockVote]:
        # TODO: Temporary mocking...

        vote_dumped = {
            "!type": "loopchain.blockchain.votes.v1_0.vote.BlockVote",
            "!data": {
                "validator": "hx9f049228bade72bc0a3490061b824f16bbb74589",
                "timestamp": "0x58b01eba4c3fe",
                "blockHeight": "0x16",
                "blockHash": "0x0399e62d77438f940dd207a2ba4593d2b231214606140c0ee6fa8f4fa7ff1d3c",
                "commitHash": "0x0399e62d77438f940dd207a2ba4593d2b231214606140c0ee6fa8f4fa7ff1d3d",
                "stateHash": "0x0399e62d77438f940dd207a2ba4593d2b231214606140c0ee6fa8f4fa7ff1d3e",
                "receiptHash": "0x0399e62d77438f940dd207a2ba4593d2b231214606140c0ee6fa8f4fa7ff1d3f",
                "nextValidatorsHash": "0x0399e62d77438f940dd207a2ba4593d2b231214606140c0ee6fa8f4fa7ff1d3f",
                "epoch": "0x2",
                "round": "0x1",
                "signature": "aC8qGOAO5Fz/lNVZW5nHdR8MiNj5WaDr+2IimKiYJ9dAXLQoaolOU/"
                             "Zmefp9L1lTxAAvbkmWCZVtQpj1lMHClQE="
            }
        }
        return [BlockVote.deserialize(vote_dumped)]

    @pytest.mark.asyncio
    async def test_create_data(self, block_factory: v1_0.BlockFactory, prev_votes: List[BlockVote]):
        # TODO: Enhance test cases after BlockVerifier implemented...

        # GIVEN I have required data to create block
        prev_hash = Hash32.new()
        height = 10

        # WHEN I create block
        block: v1_0.Block = await block_factory.create_data(
            data_number=height,
            prev_id=prev_hash,
            epoch_num=1,
            round_num=1,
            prev_votes=prev_votes
        )

        # THEN It should be return v1.0 block
        assert block.header.version == v1_0.version
        assert block.is_real()

    @pytest.mark.asyncio
    async def test_create_none_data(self, block_factory: v1_0.BlockFactory):
        # WHEN I create none block
        epoch_num = 1
        round_num = 1
        proposer_id = ExternalAddress.empty()
        block = block_factory.create_none_data(epoch_num, round_num, proposer_id)

        # THEN It should be a none block
        assert not block.is_lazy()
        assert block.is_none()

    @pytest.mark.asyncio
    async def test_create_none_data(self, block_factory: v1_0.BlockFactory):
        # WHEN I create lazy block
        epoch_num = 1
        round_num = 1
        proposer_id = ExternalAddress.empty()
        block = block_factory.create_lazy_data(epoch_num, round_num, proposer_id)

        # THEN It should be a lazy block
        assert block.is_lazy()
        assert not block.is_none()
