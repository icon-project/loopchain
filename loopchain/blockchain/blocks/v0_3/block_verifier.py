from typing import TYPE_CHECKING
from . import BlockHeader
from .. import BlockVerifier as BaseBlockVerifier, BlockBuilder

if TYPE_CHECKING:
    from .. import Block, BlockBody
    from ... import ExternalAddress


class BlockVerifier(BaseBlockVerifier):
    version = BlockHeader.version

    def _verify_common(self, block: 'Block', prev_block: 'Block', generator: 'ExternalAddress'=None):
        header: BlockHeader = block.header
        body: BlockBody = block.body

        builder = BlockBuilder.from_new(block, self._tx_versioner)
        builder.reset_cache()
        builder.peer_id = generator
        builder.signature = block.header.signature

        for tx in body.transactions.values():
            builder.transactions[tx.hash] = tx

        invoke_result = None
        if self.invoke_func:
            new_block, invoke_result = self.invoke_func(block)
            if header.state_root_hash != new_block.header.state_root_hash:
                raise RuntimeError(f"Block({header.height}, {header.hash.hex()}, "
                                   f"StateRootHash({header.state_root_hash}), "
                                   f"Expected({new_block.header.state_root_hash}).")
            builder.state_root_hash = new_block.header.state_root_hash

            builder.receipts = invoke_result
            builder.build_receipt_root_hash()
            if header.receipt_root_hash != builder.receipt_root_hash:
                raise RuntimeError(f"Block({header.height}, {header.hash.hex()}, "
                                   f"ReceiptRootHash({header.receipt_root_hash.hex()}), "
                                   f"Expected({builder.receipt_root_hash.hex()}).")

        builder.build_transaction_root_hash()
        if header.transaction_root_hash != builder.transaction_root_hash:
            raise RuntimeError(f"Block({header.height}, {header.hash.hex()}, "
                               f"TransactionRootHash({header.transaction_root_hash.hex()}), "
                               f"Expected({builder.transaction_root_hash.hex()}).")

        builder.build_hash()
        if header.hash != builder.hash:
            raise RuntimeError(f"Block({header.height}, {header.hash.hex()}, "
                               f"Hash({header.hash.hex()}, "
                               f"Expected({builder.hash.hex()}).")

        if generator:
            self.verify_generator(block, generator)

        return invoke_result

    def verify_generator(self, block: 'Block', generator: 'ExternalAddress'):
        if block.header.peer_id != generator:
            raise RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()}, "
                               f"Generator({block.header.peer_id.hex_xx()}), "
                               f"Expected({generator.hex_xx()}).")

    def verify_prev_block(self, block: 'Block', prev_block: 'Block'):
        super().verify_prev_block(block, prev_block)

        prev_block_header: BlockHeader = prev_block.header
        block_header: BlockHeader = block.header

        if prev_block_header.next_leader and \
           prev_block_header.next_leader != block_header.peer_id:
                raise RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()}, "
                                   f"Leader({block_header.peer_id.hex_xx()}), "
                                   f"Expected({prev_block_header.next_leader.hex_xx()}).")
