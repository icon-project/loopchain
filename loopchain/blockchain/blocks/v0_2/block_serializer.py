from . import BlockHeader, BlockBody
from .. import Block, v0_1a


class BlockSerializer(v0_1a.BlockSerializer):
    version = BlockHeader.version
    BlockHeaderClass = BlockHeader
    BlockBodyClass = BlockBody

    def _serialize(self, block: 'Block'):
        header: BlockHeader = block.header
        block_serialized = super()._serialize(block)
        block_serialized["next_leader"] = header.next_leader.hex_xx()
        return block_serialized
