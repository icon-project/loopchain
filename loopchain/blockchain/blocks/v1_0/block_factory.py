import time
from typing import TYPE_CHECKING, Sequence

from lft.consensus.epoch import EpochPool
from lft.consensus.messages.data import DataFactory

from loopchain import configure_default as conf
from loopchain import utils
from loopchain.blockchain import Hash32, TransactionStatusInQueue, ExternalAddress
from loopchain.blockchain.blocks.v1_0.block import Block, BlockHeader
from loopchain.blockchain.blocks.v1_0.block_builder import BlockBuilder
from loopchain.blockchain.blocks.v1_0.block_verifier import BlockVerifier
from loopchain.blockchain.invoke_result import InvokeData, InvokePool
from loopchain.blockchain.transactions import Transaction, TransactionVerifier, TransactionSerializer
from loopchain.crypto.signature import Signer
from loopchain.store.key_value_store import KeyValueStore

if TYPE_CHECKING:
    from loopchain.blockchain.votes.v1_0.vote import BlockVote
    from loopchain.baseservice.aging_cache import AgingCache
    from loopchain.store.key_value_store_plyvel import KeyValueStorePlyvel


class BlockFactory(DataFactory):
    NoneData = Hash32.empty()
    LazyData = Hash32(bytes([255] * 32))

    def __init__(self, epoch_pool_with_app, tx_queue: 'AgingCache', db: KeyValueStore, tx_versioner, invoke_pool: InvokePool, signer):
        self._epoch_pool: EpochPool = epoch_pool_with_app
        self._tx_versioner = tx_versioner

        self._tx_queue: 'AgingCache' = tx_queue
        self._invoke_pool: InvokePool = invoke_pool
        self._db: 'KeyValueStorePlyvel' = db  # TODO: Will be replaced as DB Component
        self._last_block: Block = ""  # FIXME: store it in memory or get it from db

        # From BlockBuilder
        self._signer: Signer = signer

    async def create_data(self, data_number: int, prev_id: bytes, epoch_num: int, round_num: int,
                          prev_votes: Sequence['BlockVote']) -> Block:
        """Collect tx to make a block. invoke is not done here.

        :param data_number:
        :param prev_id:
        :param epoch_num:
        :param round_num:
        :param prev_votes:
        :return: Block
        """
        prev_id: Hash32

        # Epoch.makeup_block
        block_builder = BlockBuilder.new(BlockHeader.version, self._tx_versioner)
        block_builder.fixed_timestamp = int(time.time() * 1_000_000)
        block_builder.prev_votes = prev_votes

        invoke_data: InvokeData = self._invoke_pool.prepare_invoke(epoch_num, round_num)
        self._add_tx_to_block(block_builder, invoke_data.added_transactions)

        # ConsensusSiever.__build_candidate_block
        block_builder.height = data_number
        block_builder.prev_hash = prev_id
        block_builder.signer = self._signer

        block_builder.validators_hash = invoke_data.validators_hash
        block_builder.next_validators = [ExternalAddress.fromhex(next_validator_info["id"])
                                         for next_validator_info in invoke_data.next_validators]

        block_builder.epoch = epoch_num
        block_builder.round = round_num

        # TODO: Add additional params to block_builder
        block: Block = block_builder.build()

        return block

    def _add_tx_to_block(self, block_builder: BlockBuilder, added_transactions):
        self._process_added_transactions(block_builder, added_transactions)

        tx_queue: 'AgingCache' = self._tx_queue

        block_tx_size = 0
        tx_versioner = self._tx_versioner

        while tx_queue:
            if block_tx_size >= conf.MAX_TX_SIZE_IN_BLOCK:
                utils.logger.warning(
                    f"consensus_base total size({block_builder.size()}) "
                    f"count({len(block_builder.transactions)}) "
                    f"_txQueue size ({len(tx_queue)})")
                break

            tx: 'Transaction' = tx_queue.get_item_in_status(
                get_status=TransactionStatusInQueue.normal,
                set_status=TransactionStatusInQueue.added_to_block
            )
            if tx is None:
                break

            block_timestamp = block_builder.fixed_timestamp
            if not utils.is_in_time_boundary(tx.timestamp, conf.TIMESTAMP_BOUNDARY_SECOND, block_timestamp):
                utils.logger.info(f"fail add tx to block by TIMESTAMP_BOUNDARY_SECOND"
                                  f"({conf.TIMESTAMP_BOUNDARY_SECOND}) "
                                  f"tx({tx.hash}), timestamp({tx.timestamp})")
                continue

            tv = TransactionVerifier.new(tx.version, tx.type(), tx_versioner)

            try:
                # FIXME: Currently TransactionVerifier uses `Blockchain` to check uniqueness of tx.
                # FIXME: To cut the dependencies with `Blockchain`, implement related methods into db store.
                tv.verify(tx, blockchain=self._db)
            except Exception as e:
                utils.logger.warning(
                    f"tx hash invalid. tx: {tx} exception: {e}", exc_info=e)
            else:
                block_builder.transactions[tx.hash] = tx
                block_tx_size += tx.size(tx_versioner)

    def _process_added_transactions(self, block_builder, added_transactions):
        for tx_data in added_transactions.values():  # type: dict
            tx_version, tx_type = self._tx_versioner.get_version(tx_data)
            ts = TransactionSerializer.new(tx_version, tx_type, self._tx_versioner)
            tx = ts.from_(tx_data)
            block_builder.transactions[tx.hash] = tx

    def create_none_data(self, epoch_num: int, round_num: int, proposer_id: bytes) -> Block:
        pass

    def create_lazy_data(self, epoch_num: int, round_num: int, proposer_id: bytes) -> Block:
        pass

    async def create_data_verifier(self) -> BlockVerifier:
        return BlockVerifier()
