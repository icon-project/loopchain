from typing import TYPE_CHECKING
from . import BlockBuilder
from .. import BlockVerifier as BaseBlockVerifier
from ... import TransactionVerifier

if TYPE_CHECKING:
    from . import BlockHeader, BlockBody
    from .. import Block


class BlockVerifier(BaseBlockVerifier):
    def verify(self, block: 'Block', prev_block: 'Block', blockchain=None):
        header: BlockHeader = block.header
        body: BlockBody = block.body

        if header.timestamp is None:
            raise RuntimeError

        if header.height > 0 and header.prev_hash is None:
            raise RuntimeError

        builder = BlockBuilder()
        builder.height = header.height
        builder.prev_hash = header.prev_hash
        builder.fixed_timestamp = header.timestamp

        for tx in body.transactions.values():
            builder.transactions[tx.hash] = tx

        invoke_result = None
        if self.invoke_func:
            new_block, invoke_result = self.invoke_func(block)
            if header.commit_state != new_block.header.commit_state:
                raise RuntimeError

        builder.build_merkle_tree_root_hash()
        if header.merkle_tree_root_hash != builder.merkle_tree_root_hash:
            raise RuntimeError

        builder.build_hash()
        if header.hash != builder.hash:
            raise RuntimeError

        if block.header.height > 0:
            self.verify_signature(block)
        self.verify_transactions(block, blockchain)

        if prev_block:
            self.verify_by_prev_block(block, prev_block)

        return invoke_result

    def verify_transactions(self, block: 'Block', blockchain=None):
        for tx in block.body.transactions.values():
            tv = TransactionVerifier.new(tx.version, 0)
            tv.verify(tx, blockchain)

    def verify_by_prev_block(self, block: 'Block', prev_block: 'Block'):
        if block.header.prev_hash != prev_block.header.hash:
            raise RuntimeError

        if block.header.height != prev_block.header.height + 1:
            raise RuntimeError
