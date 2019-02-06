from typing import TYPE_CHECKING
from . import BlockHeader, BlockBody
from .. import v0_1a
from .. import Block

if TYPE_CHECKING:
    from ... import TransactionVersioner


class BlockBuilder(v0_1a.BlockBuilder):
    version = BlockHeader.version
    BlockHeaderClass = BlockHeader
    BlockBodyClass = BlockBody

    def __init__(self, tx_versioner: 'TransactionVersioner'):
        super().__init__(tx_versioner)
        self.is_complain = False

    def reset_cache(self):
        super().reset_cache()
        self.is_complain = False

    def build_block_header_data(self):
        header_data = super().build_block_header_data()
        header_data["is_complain"] = self.is_complain
        return header_data

    def from_(self, block: 'Block'):
        super().from_(block)

        header: BlockHeader = block.header
        self.next_leader = header.next_leader
        self.commit_state = header.commit_state
        self.merkle_tree_root_hash = header.merkle_tree_root_hash
        self.fixed_timestamp = header.timestamp

        self._timestamp = header.timestamp
        self.is_complain = header.is_complain

        body: BlockBody = block.body
        self.confirm_prev_block = body.confirm_prev_block
