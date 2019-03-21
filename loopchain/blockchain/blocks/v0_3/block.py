from dataclasses import dataclass
from loopchain.crypto.hashing import build_hash_generator
from .. import BlockHeader as BaseBlockHeader, BlockBody as BaseBlockBody
from ... import Hash32, Address


@dataclass(frozen=True)
class BlockHeader(BaseBlockHeader):
    complained: bool
    next_leader: Address

    transaction_root_hash: Hash32
    state_root_hash: Hash32
    receipt_root_hash: Hash32

    version = "0.3"


@dataclass(frozen=True)
class BlockBody(BaseBlockBody):
    confirm_prev_block: bool


receipt_hash_generator = build_hash_generator(1, "icx_receipt")
