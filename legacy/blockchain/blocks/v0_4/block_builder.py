from typing import List

from legacy.blockchain.blocks import BlockBuilder as BaseBlockBuilder, BlockProverType
from legacy.blockchain.blocks.block import NextRepsChangeReason
from legacy.blockchain.blocks.v0_3 import BlockBuilder
from legacy.blockchain.blocks.v0_4 import BlockHeader, BlockBody, BlockProver
from legacy.blockchain.transactions import TransactionVersioner
from legacy.blockchain.types import ExternalAddress, Hash32, BloomFilter
from legacy.blockchain.votes.v0_4 import BlockVote, LeaderVote


class BlockBuilder(BlockBuilder):
    version = BlockHeader.version
    BlockHeaderClass = BlockHeader
    BlockBodyClass = BlockBody

    def __init__(self, tx_versioner: 'TransactionVersioner'):
        BaseBlockBuilder.__init__(self, tx_versioner)

        # Attributes that must be assigned
        self.reps: List[ExternalAddress] = None
        self.next_reps: List[ExternalAddress] = None
        self.next_reps_hash: Hash32 = None
        self.next_reps_change_reason: NextRepsChangeReason = NextRepsChangeReason.NoChange
        self.leader_votes: List[LeaderVote] = []
        self.prev_votes: List[BlockVote] = None

        # Attributes to be assigned(optional)
        self.fixed_timestamp: int = None
        self.state_hash: 'Hash32' = None
        self.next_leader: 'ExternalAddress' = None
        self.is_max_made_block_count: bool = None

        # Attributes to be generated
        self.transactions_hash: 'Hash32' = None
        self.receipts_hash: 'Hash32' = None
        self.reps_hash: 'Hash32' = None
        self.leader_votes_hash: 'Hash32' = None
        self.prev_votes_hash: 'Hash32' = None
        self.logs_bloom: 'BloomFilter' = None
        self._timestamp: int = None
        self._receipts: list = None

    def build_reps_hash(self):
        if self.reps_hash is not None:
            return self.reps_hash

        self.reps_hash = self._build_reps_hash()
        return self.reps_hash

    def build_next_reps_hash(self):
        if self.next_reps_hash is not None:
            return self.next_reps_hash

        self.next_reps_hash = self._build_next_reps_hash()
        return self.next_reps_hash

    def _build_next_reps_hash(self):
        block_prover = BlockProver((rep.extend() for rep in self.next_reps), BlockProverType.Rep)
        return block_prover.get_proof_root()

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
