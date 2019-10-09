from dataclasses import dataclass
from typing import List, Optional

from loopchain.baseservice import PrepChangedReason
from loopchain.blockchain.blocks import BlockHeader as BaseBlockHeader, BlockBody as BaseBlockBody
from loopchain.blockchain.types import Hash32, ExternalAddress, BloomFilter
from loopchain.blockchain.votes.v0_3 import BlockVote, LeaderVote
from loopchain.crypto.hashing import build_hash_generator


@dataclass(frozen=True)
class BlockHeader(BaseBlockHeader):
    next_leader: ExternalAddress

    logs_bloom: BloomFilter
    transactions_hash: Hash32
    state_hash: Hash32
    receipts_hash: Hash32
    reps_hash: Hash32
    next_reps_hash: Hash32
    leader_votes_hash: Hash32
    prev_votes_hash: Hash32

    version = "0.3"

    @property
    def complained(self):
        return self.leader_votes_hash != Hash32.empty()

    @property
    def prep_changed(self) -> Optional[PrepChangedReason]:
        """Return reason for prep changed

        :return: None means there is no change.
        """
        if self.next_reps_hash == Hash32.empty():
            return None

        if self.next_leader == ExternalAddress.empty():
            return PrepChangedReason.TERM_END

        return PrepChangedReason.PENALTY

    @property
    def is_unrecorded(self) -> bool:
        """Return is unrecorded block

        :return: bool
        """
        return (self.next_leader == ExternalAddress.empty() and
                self.reps_hash == self.next_reps_hash == Hash32.empty())

    @property
    def revealed_next_reps_hash(self):
        if self.prep_changed:
            return self.next_reps_hash
        return self.reps_hash


@dataclass(frozen=True)
class BlockBody(BaseBlockBody):
    leader_votes: List[LeaderVote]
    prev_votes: List[BlockVote]


receipts_hash_generator = build_hash_generator(1, "icx_receipt")
