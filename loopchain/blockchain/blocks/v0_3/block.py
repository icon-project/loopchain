from dataclasses import dataclass
from .. import BlockHeader as BaseBlockHeader, BlockBody as BaseBlockBody
from ... import Hash32, Address


@dataclass(frozen=True)
class BlockHeader(BaseBlockHeader):
    complained: bool
    next_leader: Address

    transaction_root_hash: Hash32
    state_root_hash: Hash32

    version = "0.3"


@dataclass(frozen=True)
class BlockBody(BaseBlockBody):
    pass
