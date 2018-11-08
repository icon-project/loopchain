from dataclasses import dataclass
from .. import BlockHeader as BaseBlockHeader, BlockBody as BaseBlockBody
from ... import Hash32, Address


@dataclass(frozen=True)
class BlockHeader(BaseBlockHeader):
    next_leader: Address
    merkle_tree_root_hash: Hash32
    commit_state: dict

    version = "0.1a"


@dataclass(frozen=True)
class BlockBody(BaseBlockBody):
    votes: bool
