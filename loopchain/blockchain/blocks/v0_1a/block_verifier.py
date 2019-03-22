from typing import TYPE_CHECKING

from . import BlockHeader
from .. import BlockBuilder, BlockVerifier as BaseBlockVerifier

if TYPE_CHECKING:
    from . import BlockBody
    from .. import Block
    from ... import ExternalAddress


class BlockVerifier(BaseBlockVerifier):
    version = BlockHeader.version

    def _verify_common(self, block: 'Block', prev_block: 'Block', generator: 'ExternalAddress'=None, **kwargs):
        header: BlockHeader = block.header
        body: BlockBody = block.body

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

        if generator:
            self.verify_generator(block, generator)

        return invoke_result

    def verify_prev_block(self, block: 'Block', prev_block: 'Block'):
        super().verify_prev_block(block, prev_block)
        prev_block_header: BlockHeader = prev_block.header
        block_header: BlockHeader = block.header

        if not block_header.complained and prev_block_header.next_leader and \
                prev_block_header.next_leader != block_header.peer_id:
            raise RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()}, "
                               f"Leader({block_header.peer_id.hex_xx()}), "
                               f"Expected({prev_block_header.next_leader.hex_xx()}).")

    def verify_generator(self, block: 'Block', generator: 'ExternalAddress'):
        block_header: BlockHeader = block.header
        if not block_header.complained and block.header.peer_id != generator:
            raise RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()}, "
                               f"Generator({block.header.peer_id.hex_xx()}), "
                               f"Expected({generator.hex_xx()}).")
