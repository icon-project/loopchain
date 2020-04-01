from legacy.blockchain.blocks.v0_3 import BlockSerializer
from legacy.blockchain.blocks.v0_4 import BlockHeader, BlockBody


class BlockSerializer(BlockSerializer):
    version = BlockHeader.version
    BlockHeaderClass = BlockHeader
    BlockBodyClass = BlockBody
