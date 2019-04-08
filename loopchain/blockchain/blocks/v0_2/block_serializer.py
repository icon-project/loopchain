from loopchain.blockchain.blocks import v0_1a
from loopchain.blockchain.blocks.v0_2 import BlockHeader, BlockBody


class BlockSerializer(v0_1a.BlockSerializer):
    version = BlockHeader.version
    BlockHeaderClass = BlockHeader
    BlockBodyClass = BlockBody
