from loopchain.blockchain.blocks import v0_1a
from loopchain.blockchain.blocks.v0_2 import BlockHeader


class BlockProver(v0_1a.BlockProver):
    version = BlockHeader.version
