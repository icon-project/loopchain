from dataclasses import dataclass

from loopchain.blockchain.blocks import v0_4


@dataclass(frozen=True)
class BlockHeader(v0_4.BlockHeader):
    version = "0.5"


BlockBody = v0_4.BlockBody
