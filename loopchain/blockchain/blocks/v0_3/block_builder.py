import time
from functools import reduce
from operator import or_
from typing import List
from loopchain import configure as conf
from loopchain.blockchain.types import ExternalAddress, Hash32, BloomFilter
from loopchain.blockchain.transactions import TransactionVersioner
from loopchain.blockchain.blocks import Block, BlockBuilder as BaseBlockBuilder, BlockProverType
from loopchain.blockchain.blocks.v0_3 import BlockHeader, BlockBody, BlockProver
from loopchain.blockchain.votes.v0_3 import BlockVotes, LeaderVotes


class BlockBuilder(BaseBlockBuilder):
    version = BlockHeader.version
    BlockHeaderClass = BlockHeader
    BlockBodyClass = BlockBody

    def __init__(self, tx_versioner: 'TransactionVersioner'):
        super().__init__(tx_versioner)

        # Attributes that must be assigned
        self.reps: List[ExternalAddress] = None
        self.leader_votes: LeaderVotes = LeaderVotes([], conf.LEADER_COMPLAIN_RATIO, -1, ExternalAddress.empty())
        self.prev_votes: BlockVotes = None
        self.next_leader: 'ExternalAddress' = None

        # Attributes to be assigned(optional)
        self.fixed_timestamp: int = None
        self.state_hash: 'Hash32' = None

        # Attributes to be generated
        self.transaction_hash: 'Hash32' = None
        self.receipt_hash: 'Hash32' = None
        self.rep_hash: 'Hash32' = None
        self.leader_vote_hash: 'Hash32' = None
        self.prev_vote_hash: 'Hash32' = None
        self.bloom_filter: 'BloomFilter' = None
        self._timestamp: int = None
        self._receipts: list = None

    @property
    def receipts(self):
        return self._receipts

    @receipts.setter
    def receipts(self, receipts):
        if not receipts:
            receipts = {}

        if len(self.transactions) != len(receipts):
            raise RuntimeError("Transactions and Receipts are not matched.")

        self._receipts = [dict(receipts[tx_hash.hex()]) for tx_hash in self.transactions]

    def reset_cache(self):
        super().reset_cache()

        self.transaction_hash = None
        self.receipt_hash = None
        self.rep_hash = None
        self.leader_vote_hash = None
        self.prev_vote_hash = None
        self.bloom_filter = None
        self._timestamp = None

    def build(self):
        self.build_peer_id()
        self.build_hash()
        self.sign()

        self.block = self.build_block()
        return self.block

    def build_block_header_data(self) -> dict:
        return {
            "hash": self.hash,
            "prev_hash": self.prev_hash,
            "height": self.height,
            "timestamp": self._timestamp,
            "peer_id": self.peer_id,
            "signature": self.signature,
            "next_leader": self.next_leader,
            "transaction_hash": self.transaction_hash,
            "state_hash": self.state_hash,
            "receipt_hash": self.receipt_hash,
            "rep_hash": self.rep_hash,
            "leader_vote_hash": self.leader_vote_hash,
            "prev_vote_hash": self.prev_vote_hash,
            "bloom_filter": self.bloom_filter,
        }

    def build_block_body_data(self) -> dict:
        return {
            "transactions": self.transactions,
            "leader_votes": self.leader_votes,
            "prev_votes": self.prev_votes
        }

    def build_transaction_hash(self):
        if self.transaction_hash is not None:
            return self.transaction_hash

        self.transaction_hash = self._build_transaction_hash()
        return self.transaction_hash

    def _build_transaction_hash(self):
        if not self.transactions:
            return Hash32.empty()

        block_prover = BlockProver(self.transactions.keys(), BlockProverType.Transaction)
        return block_prover.get_proof_root()

    def build_receipt_hash(self):
        if self.receipt_hash is not None:
            return self.receipt_hash

        self.receipt_hash = self._build_receipt_hash()
        return self.receipt_hash

    def _build_receipt_hash(self):
        if not self.receipts:
            return Hash32.empty()

        block_prover = BlockProver(self.receipts, BlockProverType.Receipt)
        return block_prover.get_proof_root()

    def build_rep_hash(self):
        if self.rep_hash is not None:
            return self.rep_hash

        self.rep_hash = self._build_rep_hash()
        return self.rep_hash

    def _build_rep_hash(self):
        block_prover = BlockProver(self.reps, BlockProverType.Rep)
        return block_prover.get_proof_root()

    def build_leader_vote_hash(self):
        if self.leader_vote_hash is not None:
            return self.leader_vote_hash

        self.leader_vote_hash = self._build_leader_vote_hash()
        return self.leader_vote_hash

    def _build_leader_vote_hash(self):
        block_prover = BlockProver((vote.hash() for vote in self.leader_votes.votes),
                                   BlockProverType.Vote)
        return block_prover.get_proof_root()

    def build_prev_vote_hash(self):
        if self.prev_vote_hash is not None:
            return self.prev_vote_hash

        self.prev_vote_hash = self._build_prev_vote_hash()
        return self.prev_vote_hash

    def _build_prev_vote_hash(self):
        block_prover = BlockProver((vote.hash() for vote in self.prev_votes.votes),
                                   BlockProverType.Vote)
        return block_prover.get_proof_root()

    def build_bloom_filter(self):
        if self.bloom_filter is not None:
            return self.bloom_filter

        self.bloom_filter = self._build_bloom_filter()
        return self.bloom_filter

    def _build_bloom_filter(self):
        if not self.receipts:
            return BloomFilter.new()

        bloom_filters = (BloomFilter.fromhex(receipt["logsBloom"])
                         for receipt in self.receipts if "logsBloom" in receipt)
        return BloomFilter(reduce(or_, bloom_filters, BloomFilter.new()))

    def build_hash(self):
        if self.hash is not None:
            return self.hash

        if self.height > 0 and self.prev_hash is None:
            raise RuntimeError

        self.build_transaction_hash()
        self.build_receipt_hash()
        self.build_rep_hash()
        self.build_leader_vote_hash()
        self.build_prev_vote_hash()
        self.build_bloom_filter()
        self.hash = self._build_hash()
        return self.hash

    def _build_hash(self):
        if self.fixed_timestamp is not None:
            self._timestamp = self.fixed_timestamp
        else:
            self._timestamp = int(time.time() * 1_000_000)

        leaves = (
            self.prev_hash,
            self.transaction_hash,
            self.rep_hash,
            self.leader_vote_hash,
            self.prev_vote_hash,
            self.bloom_filter,
            self.height,
            self._timestamp,
            self.peer_id,
        )
        block_prover = BlockProver(leaves, BlockProverType.Block)
        return block_prover.get_proof_root()

    def from_(self, block: 'Block'):
        super().from_(block)

        header: BlockHeader = block.header

        self.next_leader = header.next_leader
        self.transaction_hash = header.transaction_hash
        self.state_hash = header.state_hash
        self.receipt_hash = header.receipt_hash
        self.rep_hash = header.rep_hash
        self.leader_vote_hash = header.leader_vote_hash
        self.prev_vote_hash = header.prev_vote_hash
        self.bloom_filter = header.bloom_filter
        self.fixed_timestamp = header.timestamp
        self._timestamp = header.timestamp

        body: BlockBody = block.body
        self.leader_votes = body.leader_votes
        self.prev_votes = body.prev_votes
