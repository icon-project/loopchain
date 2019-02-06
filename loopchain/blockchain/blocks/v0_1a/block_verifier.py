from typing import TYPE_CHECKING

from . import BlockHeader
from .. import BlockBuilder, BlockVerifier as BaseBlockVerifier
from ... import TransactionVerifier

if TYPE_CHECKING:
    from . import BlockBody
    from .. import Block
    from ... import ExternalAddress


class BlockVerifier(BaseBlockVerifier):
    version = BlockHeader.version

    def verify(self, block: 'Block', prev_block: 'Block', blockchain=None, generator: 'ExternalAddress'=None):
        self.verify_transactions(block, blockchain)
        return self.verify_common(block, prev_block, generator)

    def verify_loosely(self, block: 'Block', prev_block: 'Block', blockchain=None, generator: 'ExternalAddress'=None):
        self.verify_transactions_loosely(block, blockchain)
        return self.verify_common(block, prev_block, generator)

    def verify_common(self, block: 'Block', prev_block: 'Block', generator: 'ExternalAddress'=None):
        header: BlockHeader = block.header
        body: BlockBody = block.body

        if header.timestamp is None:
            raise RuntimeError(f"Block({header.height}, {header.hash.hex()} does not have timestamp.")

        if header.height > 0 and header.prev_hash is None:
            raise RuntimeError(f"Block({header.height}, {header.hash.hex()} does not have prev_hash.")

        self.verify_version(block)

        builder = BlockBuilder.new(self.version, self._tx_versioner)
        builder.height = header.height
        builder.prev_hash = header.prev_hash
        builder.fixed_timestamp = header.timestamp

        for tx in body.transactions.values():
            builder.transactions[tx.hash] = tx

        invoke_result = None
        if self.invoke_func:
            new_block, invoke_result = self.invoke_func(block)
            if not header.commit_state and len(body.transactions) == 0:
                # vote block
                pass
            elif header.commit_state != new_block.header.commit_state:
                raise RuntimeError(f"Block({header.height}, {header.hash.hex()}, "
                                   f"CommitState({header.commit_state}), "
                                   f"Expected({new_block.header.commit_state}).")

        builder.build_merkle_tree_root_hash()
        if header.merkle_tree_root_hash != builder.merkle_tree_root_hash:
            raise RuntimeError(f"Block({header.height}, {header.hash.hex()}, "
                               f"MerkleTreeRootHash({header.merkle_tree_root_hash.hex()}), "
                               f"Expected({builder.merkle_tree_root_hash.hex()}).")

        builder.build_hash()
        if header.hash != builder.hash:
            raise RuntimeError(f"Block({header.height}, {header.hash.hex()}, "
                               f"Hash({header.hash.hex()}, "
                               f"Expected({builder.hash.hex()}).")

        if block.header.height > 0:
            self.verify_signature(block)

        if prev_block:
            self.verify_prev_block(block, prev_block)

        if generator:
            self.verify_generator(block, generator)

        return invoke_result

    def verify_transactions(self, block: 'Block', blockchain=None):
        for tx in block.body.transactions.values():
            tv = TransactionVerifier.new(tx.version, self._tx_versioner)
            tv.verify(tx, blockchain)

    def verify_transactions_loosely(self, block: 'Block', blockchain=None):
        for tx in block.body.transactions.values():
            tv = TransactionVerifier.new(tx.version, self._tx_versioner)
            tv.verify_loosely(tx, blockchain)

    def verify_prev_block(self, block: 'Block', prev_block: 'Block'):
        if block.header.prev_hash != prev_block.header.hash:
            raise RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()}, "
                               f"PrevHash({block.header.prev_hash.hex()}), "
                               f"Expected({prev_block.header.hash.hex()}).")

        if block.header.height != prev_block.header.height + 1:
            raise RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()}, "
                               f"Height({block.header.height}), "
                               f"Expected({prev_block.header.height + 1}).")

    def verify_generator(self, block: 'Block', generator: 'ExternalAddress'):
        if block.header.peer_id != generator:
            raise RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()}, "
                               f"Generator({block.header.peer_id.hex_xx()}), "
                               f"Expected({generator.hex_xx()}).")
