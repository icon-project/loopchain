import os

import pytest

from loopchain.blockchain.blocks.v0_1a.block import BlockHeader as BlockHeader_v0_1a
from loopchain.blockchain.blocks.v0_3.block import BlockHeader as BlockHeader_v0_3
from loopchain.blockchain.blocks.v0_4.block import BlockHeader as BlockHeader_v0_4
from loopchain.blockchain.blocks.block import NextRepsChangeReason
from loopchain.blockchain.types import Address, Signature, Hash32, ExternalAddress, BloomFilter


class TestBlockHeader_v0_1a:
    @pytest.fixture
    def header_factory(self):
        def _header(hash_: Hash32 = Hash32.new(),
                    prev_hash: Hash32 = Hash32.new(),
                    height: int = 0,
                    timestamp: int = 0,
                    peer_id: ExternalAddress = ExternalAddress.new(),
                    signature: Signature = Signature.new(),
                    next_leader: Address = Address.new(),
                    merkle_tree_root_hash: Hash32 = Hash32.new(),
                    commit_state: dict = dict()) -> BlockHeader_v0_1a:

            return BlockHeader_v0_1a(hash_, prev_hash, height, timestamp, peer_id,
                                     signature, next_leader, merkle_tree_root_hash, commit_state)

        return _header

    def test_reps_hash_should_be_none(self, header_factory):
        header: BlockHeader_v0_1a = header_factory()

        assert not header.reps_hash

    def test_prep_changed_should_be_none(self, header_factory):
        header: BlockHeader_v0_1a = header_factory()

        assert not header.prep_changed

    def test_revealed_next_reps_hash_should_be_none(self, header_factory):
        header: BlockHeader_v0_1a = header_factory()

        assert not header.revealed_next_reps_hash


class TestBlockHeader_v0_3:
    @pytest.fixture
    def header_factory(self):
        def _header(hash_: Hash32 = Hash32.new(),
                    prev_hash: Hash32 = Hash32.new(),
                    height: int = 0,
                    timestamp: int = 0,
                    peer_id: ExternalAddress = ExternalAddress.new(),
                    signature: Signature = Signature.new(),
                    next_leader: ExternalAddress = ExternalAddress.new(),
                    logs_bloom: BloomFilter = BloomFilter.new(),
                    transactions_hash: Hash32 = Hash32.new(),
                    state_hash: Hash32 = Hash32.new(),
                    receipts_hash: Hash32 = Hash32.new(),
                    reps_hash: Hash32 = Hash32.new(),
                    next_reps_hash: Hash32 = Hash32.new(),
                    leader_votes_hash: Hash32 = Hash32.new(),
                    prev_votes_hash: Hash32 = Hash32.new()) -> BlockHeader_v0_3:

            return BlockHeader_v0_3(hash_, prev_hash, height, timestamp, peer_id, signature,
                                    next_leader, logs_bloom, transactions_hash,
                                    state_hash, receipts_hash, reps_hash,
                                    next_reps_hash, leader_votes_hash, prev_votes_hash)

        return _header

    def test_prep_is_not_changed_if_next_reps_hash_is_empty(self, header_factory):
        header = header_factory(next_leader=ExternalAddress(os.urandom(ExternalAddress.size)),
                                reps_hash=Hash32(os.urandom(Hash32.size)),
                                next_reps_hash=Hash32.empty())

        assert not header.prep_changed

    def test_prep_changed_by_term_end_if_next_leader_is_empty(self, header_factory):
        header = header_factory(next_leader=ExternalAddress.empty(),
                                reps_hash=Hash32(os.urandom(Hash32.size)),
                                next_reps_hash=Hash32(os.urandom(Hash32.size)))

        assert header.prep_changed
        assert header.prep_changed_reason is NextRepsChangeReason.TermEnd

    def test_prep_changed_by_penalty_if_exists_next_reps_hash_and_next_leader(self, header_factory):
        header = header_factory(next_leader=ExternalAddress(os.urandom(ExternalAddress.size)),
                                reps_hash=Hash32(os.urandom(Hash32.size)),
                                next_reps_hash=Hash32(os.urandom(Hash32.size)))

        assert header.prep_changed
        assert header.prep_changed_reason == NextRepsChangeReason.TermEnd


class TestBlockHeader_v0_4:
    @pytest.fixture
    def header_factory(self):
        def _header(hash_: Hash32 = Hash32.new(),
                    prev_hash: Hash32 = Hash32.new(),
                    height: int = 0,
                    timestamp: int = 0,
                    peer_id: ExternalAddress = ExternalAddress.new(),
                    signature: Signature = Signature.new(),
                    next_leader: ExternalAddress = ExternalAddress.new(),
                    logs_bloom: BloomFilter = BloomFilter.new(),
                    transactions_hash: Hash32 = Hash32.new(),
                    state_hash: Hash32 = Hash32.new(),
                    receipts_hash: Hash32 = Hash32.new(),
                    reps_hash: Hash32 = Hash32.new(),
                    next_reps_hash: Hash32 = Hash32.new(),
                    leader_votes_hash: Hash32 = Hash32.new(),
                    prev_votes_hash: Hash32 = Hash32.new()) -> BlockHeader_v0_4:

            return BlockHeader_v0_4(hash_, prev_hash, height, timestamp, peer_id, signature,
                                    next_leader, logs_bloom, transactions_hash,
                                    state_hash, receipts_hash, reps_hash,
                                    next_reps_hash, leader_votes_hash, prev_votes_hash)

        return _header

    def test_prep_is_not_changed_if_next_reps_hash_is_empty(self, header_factory):
        header = header_factory(next_leader=ExternalAddress(os.urandom(ExternalAddress.size)),
                                reps_hash=Hash32(os.urandom(Hash32.size)),
                                next_reps_hash=Hash32.empty())

        assert not header.prep_changed

    def test_prep_changed_by_term_end_if_next_leader_is_empty(self, header_factory):
        header = header_factory(next_leader=ExternalAddress.empty(),
                                reps_hash=Hash32(os.urandom(Hash32.size)),
                                next_reps_hash=Hash32(os.urandom(Hash32.size)))

        assert header.prep_changed
        assert header.prep_changed_reason is NextRepsChangeReason.TermEnd

    def test_prep_changed_by_penalty_if_exists_next_reps_hash_and_next_leader(self, header_factory):
        header = header_factory(next_leader=ExternalAddress(os.urandom(ExternalAddress.size)),
                                reps_hash=Hash32(os.urandom(Hash32.size)),
                                next_reps_hash=Hash32(os.urandom(Hash32.size)))

        assert header.prep_changed
        assert header.prep_changed_reason == NextRepsChangeReason.Penalty
