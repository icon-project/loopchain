from loopchain.blockchain.blocks.block import NextRepsChangeReason
from loopchain.blockchain.blocks.v0_3 import BlockBuilder as BaseBlockBuilder
from loopchain.blockchain.blocks.v0_4 import BlockHeader, BlockBody
from loopchain.blockchain.transactions import TransactionVersioner
from loopchain.blockchain.types import ExternalAddress


class BlockBuilder(BaseBlockBuilder):
    version = BlockHeader.version
    BlockHeaderClass = BlockHeader
    BlockBodyClass = BlockBody

    def __init__(self, tx_versioner: 'TransactionVersioner'):
        super().__init__(tx_versioner)

        # Attributes that must be assigned
        self.next_reps_change_reason: NextRepsChangeReason = NextRepsChangeReason.NoChange

        # Attributes to be assigned(optional)
        self.is_max_made_block_count: bool = None

    def build_next_leader(self):
        if self.next_leader is not None:
            return self.next_leader

        self.next_leader = self._build_next_leader()
        return self.next_leader

    def _build_next_leader(self):
        if self.next_reps_change_reason is NextRepsChangeReason.TermEnd:
            return ExternalAddress.empty()
        elif self.next_reps_change_reason is NextRepsChangeReason.Penalty:
            if not self.is_max_made_block_count and self.peer_id in self.next_reps:
                next_index = self.reps.index(self.peer_id)
            else:
                curr_index = self.reps.index(self.peer_id)
                next_index = curr_index + 1
            next_index = next_index if next_index < len(self.next_reps) else 0
            return self.next_reps[next_index]
        else:
            return self.next_leader

    def build_hash(self):
        if self.hash is not None:
            return self.hash

        if self.height > 0 and self.prev_hash is None:
            raise RuntimeError

        self.build_transactions_hash()
        self.build_receipts_hash()
        self.build_reps_hash()
        self.build_next_reps_hash()
        self.build_next_leader()
        self.build_leader_votes_hash()
        self.build_prev_votes_hash()
        self.build_logs_bloom()
        self.hash = self._build_hash()
        return self.hash
