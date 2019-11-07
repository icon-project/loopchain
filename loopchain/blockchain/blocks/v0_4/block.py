from dataclasses import dataclass
from typing import List, Optional

from loopchain.blockchain.blocks import (BlockHeader as BaseBlockHeader,
                                         BlockBody as BaseBlockBody, NextRepsChangeReason)
from loopchain.blockchain.types import Hash32, ExternalAddress, BloomFilter
from loopchain.blockchain.votes.v0_4 import BlockVote, LeaderVote
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

    version = "0.4"

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

        if self.next_leader == ExternalAddress.empty():
            return NextRepsChangeReason.TermEnd

        return NextRepsChangeReason.Penalty

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
