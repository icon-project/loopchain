from . import BlockHeader, BlockBody
from .. import v0_1a


class BlockBuilder(v0_1a.BlockBuilder):
    version = BlockHeader.version
    BlockHeaderClass = BlockHeader
    BlockBodyClass = BlockBody
