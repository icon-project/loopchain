from dataclasses import dataclass
from typing import List, Optional

from legacy.blockchain.blocks import (BlockHeader as BaseBlockHeader,
                                         BlockBody as BaseBlockBody, NextRepsChangeReason)
from legacy.blockchain.types import Hash32, ExternalAddress, BloomFilter
from legacy.blockchain.votes.v0_3 import BlockVote, LeaderVote
from legacy.crypto.hashing import build_hash_generator


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
    def prep_changed(self) -> bool:
        """Return reason for prep changed

        :return: False means there is no change.
        """
        return self.next_reps_hash != Hash32.empty()

    @property
    def prep_changed_reason(self) -> Optional[NextRepsChangeReason]:
        """Return prep changed reason

        :return: NextRepsChangeReason : NoChange, TermEnd, Penalty
        """
        if not self.prep_changed and not self.is_unrecorded:
            return NextRepsChangeReason.NoChange

        # block v0.3 work as TermEnd when Penalty
        return NextRepsChangeReason.TermEnd

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
