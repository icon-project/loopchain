from dataclasses import dataclass
from typing import List
from loopchain.crypto.hashing import build_hash_generator
from .. import BlockHeader as BaseBlockHeader, BlockBody as BaseBlockBody
from ... import Hash32, ExternalAddress, BloomFilter


@dataclass(frozen=True)
class BlockHeader(BaseBlockHeader):
    complained: bool
    next_leader: ExternalAddress

    transaction_root_hash: Hash32
    state_root_hash: Hash32
    receipt_root_hash: Hash32
    rep_root_hash: Hash32

    bloom_filter: BloomFilter

    version = "0.3"


@dataclass(frozen=True)
class BlockBody(BaseBlockBody):
    confirm_prev_block: bool


receipt_hash_generator = build_hash_generator(1, "icx_receipt")
