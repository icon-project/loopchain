#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2018 ICON Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os

import pytest

from loopchain.blockchain.blocks import BlockBuilder, Block
from loopchain.blockchain.blocks import v0_1a, v0_3
from loopchain.blockchain.transactions import Transaction, TransactionVersioner
from loopchain.blockchain.transactions import genesis, v2, v3
from loopchain.blockchain.types import ExternalAddress, Hash32, BloomFilter, Signature
from loopchain.blockchain.votes.v0_1a import BlockVote, BlockVotes

tx_versioner = TransactionVersioner()
tx_versions = [genesis.version, v2.version, v3.version]


@pytest.mark.parametrize("block_version", [v0_1a.version, v0_3.version])
def test_version_check(block_version):
    block_builder = BlockBuilder.new(version=block_version, tx_versioner=tx_versioner)

    if block_version == v0_1a:
        assert isinstance(block_builder, v0_1a.BlockBuilder)
    elif block_version == v0_3:
        assert isinstance(block_builder, v0_3.BlockBuilder)


class _TestBlockBuilderBase:
    @pytest.fixture
    def block_builder(self) -> BlockBuilder:
        pass

    def test_build_peer_id(self, block_builder):
        assert block_builder.signer
        assert not block_builder.peer_id
        expected_peer_id = ExternalAddress.fromhex_address(block_builder.signer.address)

        block_builder.build_peer_id()

        assert block_builder.peer_id
        assert block_builder.peer_id == expected_peer_id

    def test_build_peer_id_returns_its_peer_id_if_exists(self, block_builder):
        expected_peer_id = ExternalAddress(os.urandom(ExternalAddress.size))
        block_builder.peer_id = expected_peer_id
        assert block_builder.peer_id

        built_peer_id = block_builder.build_peer_id()

        assert built_peer_id == expected_peer_id

    def test_build_peer_id_raises_exc_if_signer_not_exists(self, block_builder):
        block_builder.signer = None
        assert not block_builder.signer
        assert not block_builder.peer_id

        with pytest.raises(RuntimeError):
            assert block_builder.build_peer_id()

    def test_sign_builds_signature(self, block_builder):
        block_builder.build_hash()
        assert block_builder.signer
        assert not block_builder.signature

        block_builder.sign()
        assert block_builder.signature

    def test_sign_returns_its_signature_if_exists(self, block_builder):
        expected_signature = Signature(os.urandom(Signature.size))
        block_builder.signature = expected_signature
        assert block_builder.signature

        block_builder.build_hash()
        signature = block_builder.sign()

        assert signature == expected_signature

    def test_sign_raises_exc_if_hash_not_exists(self, block_builder):
        assert not block_builder.signature
        assert not block_builder.hash

        with pytest.raises(RuntimeError):
            assert block_builder.sign()

    @pytest.mark.parametrize("tx_version", tx_versions)
    def test_size_check(self, block_builder, tx_factory, tx_version):
        tx_count = 5
        for _ in range(tx_count):
            tx: Transaction = tx_factory(tx_version=tx_version)
            block_builder.transactions[tx.hash] = tx

        assert block_builder.size()

    def test_reset_cache(self, block_builder):
        block_builder.block = "block "
        block_builder.hash = "hash"
        block_builder.signature = "signature"
        block_builder.peer_id = "peer_id"

        assert block_builder.block
        assert block_builder.hash
        assert block_builder.signature
        assert block_builder.peer_id

        block_builder.reset_cache()

        assert not block_builder.block
        assert not block_builder.hash
        assert not block_builder.signature
        assert not block_builder.peer_id

    def test_build(self, block_builder):
        block: Block = block_builder.build()

        assert isinstance(block, Block)
        assert block_builder.version == block.header.version


class TestBlockBuilder_v0_1a(_TestBlockBuilderBase):
    BLOCK_VERSION = v0_1a.version
    
    @pytest.fixture
    def block_builder(self, block_builder_factory) -> v0_1a.BlockBuilder:
        block_builder: v0_1a.BlockBuilder = block_builder_factory(block_version=self.BLOCK_VERSION)

        # Attributes to be assigned(optional)
        assert not block_builder.next_leader
        assert block_builder.confirm_prev_block is True
        assert not block_builder.fixed_timestamp
        
        # Attributes to be generated
        assert not block_builder.commit_state
        assert not block_builder.merkle_tree_root_hash
        
        assert not block_builder._timestamp
        
        return block_builder

    def test_reset_cache(self, block_builder):
        block_builder.merkle_tree_root_hash = Hash32(os.urandom(Hash32.size))
        block_builder.commit_state = "commit_state"
        block_builder._timestamp = "timestamp"

        assert block_builder.merkle_tree_root_hash
        assert block_builder.commit_state
        assert block_builder._timestamp

        block_builder.reset_cache()

        assert not block_builder.merkle_tree_root_hash
        assert not block_builder.commit_state
        assert not block_builder._timestamp

    def test_build_merkle_tree_root_hash(self, block_builder):
        assert block_builder.merkle_tree_root_hash is None

        block_builder.build_merkle_tree_root_hash()
        assert isinstance(block_builder.merkle_tree_root_hash, Hash32)

    def test_build_merkle_tree_root_hash_returns_its_hash_if_exists(self, block_builder):
        expected_merkle_tree_root_hash = Hash32(os.urandom(Hash32.size))
        block_builder.merkle_tree_root_hash = expected_merkle_tree_root_hash

        merkle_tree_root_hash = block_builder.build_merkle_tree_root_hash()

        assert merkle_tree_root_hash == expected_merkle_tree_root_hash

    def test_build_hash_builds_hash(self, block_builder):
        assert block_builder.hash is None

        block_builder.build_merkle_tree_root_hash()
        block_builder.build_hash()

        assert isinstance(block_builder.hash, Hash32)
        assert isinstance(block_builder.merkle_tree_root_hash, Hash32)
        assert block_builder._timestamp

    def test_build_hash_with_fixed_timestamp(self, block_builder):
        assert block_builder.hash is None
        assert block_builder.prev_hash

        expected_time_stamp = 1
        block_builder.fixed_timestamp = expected_time_stamp

        block_builder.build_merkle_tree_root_hash()
        block_builder.build_hash()

        assert isinstance(block_builder.hash, Hash32)
        assert isinstance(block_builder.merkle_tree_root_hash, Hash32)
        assert block_builder._timestamp == expected_time_stamp

    def test_build_hash_returns_its_hash_if_exists(self, block_builder):
        expected_hash = Hash32(os.urandom(Hash32.size))
        block_builder.hash = expected_hash

        block_builder.build_merkle_tree_root_hash()
        block_builder.build_hash()

        assert block_builder.hash == expected_hash

    def test_build_hash_raises_if_no_prev_hash(self, block_builder):
        block_builder.prev_hash = None
        assert block_builder.height > 0

        with pytest.raises(RuntimeError):
            block_builder.build_hash()


class TestBlockBuilder_v0_3(_TestBlockBuilderBase):
    BLOCK_VERSION = v0_3.version

    SIGNER = pytest.SIGNERS[0]
    REPS = pytest.REPS
    OLD_LEADER = pytest.REPS[0]
    NEXT_LEADER = pytest.REPS[1]
    NEW_LEADER = pytest.REPS[2]

    @pytest.fixture
    def block_builder(self, block_builder_factory) -> v0_3.BlockBuilder:
        block_builder: v0_3.BlockBuilder = block_builder_factory(block_version=self.BLOCK_VERSION)

        # Attributes that must be assigned
        assert block_builder.reps == self.REPS
        assert block_builder.next_reps_hash
        assert block_builder.leader_votes == []
        assert block_builder.prev_votes == []
        assert block_builder.next_leader

        # Check - Attributes to be assigned(optional)
        assert not block_builder.fixed_timestamp
        assert not block_builder.state_hash
        
        # Check - Attributes to be generated
        assert not block_builder.transactions_hash
        assert not block_builder.receipts_hash
        assert not block_builder.reps_hash
        assert not block_builder.leader_votes_hash
        assert not block_builder.prev_votes_hash
        assert not block_builder.logs_bloom
        assert not block_builder._timestamp
        assert not block_builder._receipts

        return block_builder

    def test_reset_cache_removes_target_members(self, block_builder):
        block_builder.transactions_hash = "transactions_hash"
        block_builder.receipts_hash = "receipts_hash"
        block_builder.reps_hash = "reps_hash"
        block_builder.leader_votes_hash = "leader_votes_hash"
        block_builder.prev_votes_hash = "prev_votes_hash"
        block_builder.logs_bloom = "logs_bloom"
        block_builder._timestamp = "_timestamp"

        assert block_builder.transactions_hash
        assert block_builder.receipts_hash
        assert block_builder.reps_hash
        assert block_builder.leader_votes_hash
        assert block_builder.prev_votes_hash
        assert block_builder.logs_bloom
        assert block_builder._timestamp

        block_builder.reset_cache()

        assert block_builder.transactions_hash is None
        assert block_builder.receipts_hash is None
        assert block_builder.reps_hash is None
        assert block_builder.leader_votes_hash is None
        assert block_builder.prev_votes_hash is None
        assert block_builder.logs_bloom is None
        assert block_builder._timestamp is None

    # ----- Transactions Hash
    @pytest.mark.parametrize("tx_version", tx_versions)
    def test_build_transactions_hash(self, block_builder, tx_factory, tx_version):
        for _ in range(5):
            tx: Transaction = tx_factory(tx_version=tx_version)
            block_builder.transactions[tx.hash] = tx
        assert block_builder.transactions
        assert not block_builder.transactions_hash

        transaction_hash = block_builder.build_transactions_hash()

        assert block_builder.transactions_hash
        assert block_builder.transactions_hash == transaction_hash
        assert block_builder.transactions_hash != Hash32.empty()

    def test_build_transactions_hash_returns_its_hash_if_exists(self, block_builder):
        expected_transactions_hash = Hash32(os.urandom(Hash32.size))
        block_builder.transactions_hash = expected_transactions_hash

        transactions_hash = block_builder.build_transactions_hash()

        assert transactions_hash == expected_transactions_hash

    def test_build_transactions_hash_returns_empty_if_transactions_not_exists(self, block_builder):
        block_builder.transactions = []
        assert not block_builder.transactions
        assert not block_builder.transactions_hash

        transactions_hash = block_builder.build_transactions_hash()

        assert transactions_hash == Hash32.empty()

    # ----- Receipts Hash
    @pytest.mark.parametrize("tx_version", tx_versions)
    def test_build_receipts_hash(self, block_builder, tx_factory, tx_version):
        dummy_receipts = {}
        for _ in range(5):
            tx: Transaction = tx_factory(tx_version=tx_version)
            block_builder.transactions[tx.hash] = tx
            dummy_receipts[tx.hash.hex()] = {
                "dummy_receipt": "dummy"
            }
        block_builder.receipts = dummy_receipts
        assert not block_builder.receipts_hash

        receipts_hash = block_builder.build_receipts_hash()

        assert receipts_hash
        assert block_builder.receipts_hash
        assert block_builder.receipts_hash == receipts_hash
        assert block_builder.receipts_hash != Hash32.empty()

    def test_build_receipts_hash_returns_its_hash_if_exists(self, block_builder):
        expected_receipts_hash = Hash32(os.urandom(Hash32.size))
        block_builder.receipts_hash = expected_receipts_hash
        assert block_builder.receipts_hash

        receipts_hash = block_builder.build_receipts_hash()

        assert receipts_hash == expected_receipts_hash

    def test_build_receipts_hash_returns_empty_if_no_receipts_exists(self, block_builder):
        assert not block_builder.receipts
        assert not block_builder.receipts_hash

        receipts_hash = block_builder.build_receipts_hash()

        assert receipts_hash == Hash32.empty()

    @pytest.mark.parametrize("tx_version", tx_versions)
    def test_set_receipts_raises_exc_if_receipts_count_ne_tx_count(self, block_builder, tx_factory, tx_version):
        dummy_receipts = {}
        for _ in range(5):
            tx: Transaction = tx_factory(tx_version=tx_version)
            block_builder.transactions[tx.hash] = tx
            dummy_receipts[tx.hash.hex()] = {
                "dummy_receipt": "dummy"
            }

        block_builder.receipts = dummy_receipts

        dummy_receipts.popitem()
        with pytest.raises(RuntimeError, match="Transactions and Receipts are not matched."):
            block_builder.receipts = dummy_receipts

    # ----- Reps Hash
    def test_build_reps_hash(self, block_builder):
        assert not block_builder.reps_hash
        assert block_builder.next_reps_hash

        reps_hash = block_builder.build_reps_hash()

        assert reps_hash
        assert block_builder.reps_hash
        assert block_builder.reps_hash == reps_hash

    def test_build_reps_hash_sets_next_reps_hash_as_current_reps_hash_if_not_exists(self, block_builder):
        block_builder.next_reps_hash = None
        assert not block_builder.reps_hash
        assert not block_builder.next_reps_hash

        reps_hash = block_builder.build_reps_hash()

        assert reps_hash
        assert block_builder.reps_hash
        assert block_builder.reps_hash == reps_hash
        assert block_builder.reps_hash == block_builder.next_reps_hash

    def test_build_reps_hash_returns_its_hash_if_exists(self, block_builder):
        expected_reps_hash = Hash32(os.urandom(Hash32.size))
        block_builder.reps_hash = expected_reps_hash

        reps_hash = block_builder.build_reps_hash()

        assert reps_hash == expected_reps_hash

    # ----- Leader Votes Hash
    def test_build_leader_votes_hash(self, block_builder):
        assert not block_builder.leader_votes_hash

        leader_votes_hash = block_builder.build_leader_votes_hash()

        assert block_builder.leader_votes_hash
        assert block_builder.leader_votes_hash == leader_votes_hash

    def test_build_leader_votes_hash_returns_its_hash_if_exists(self, block_builder):
        expected_leader_votes_hash = Hash32(os.urandom(Hash32.size))
        block_builder.leader_votes_hash = expected_leader_votes_hash

        leader_votes_hash = block_builder.build_leader_votes_hash()

        assert leader_votes_hash == expected_leader_votes_hash

    # ----- Leader Votes Hash
    def test_build_prev_votes_hash(self, block_builder, block_vote_factory, block_votes_factory):
        block_hash = Hash32(os.urandom(Hash32.size))
        block_vote: BlockVote = block_vote_factory(signer=self.SIGNER, block_hash=block_hash)
        block_votes: BlockVotes = block_votes_factory(reps=self.REPS, block_hash=block_hash)
        block_votes.add_vote(block_vote)

        block_builder.prev_votes = block_votes.votes
        assert block_builder.prev_votes
        assert not block_builder.prev_votes_hash

        prev_votes_hash = block_builder.build_prev_votes_hash()

        assert prev_votes_hash == block_builder.prev_votes_hash

    def test_build_prev_votes_hash_returns_its_hash_if_exists(self, block_builder):
        expected_prev_votes_hash = Hash32(os.urandom(Hash32.size))
        block_builder.prev_votes_hash = expected_prev_votes_hash

        prev_votes_hash = block_builder.build_prev_votes_hash()

        assert prev_votes_hash == expected_prev_votes_hash

    def test_build_prev_votes_hash_sets_empty_if_prev_votes_not_exists(self, block_builder):
        block_builder.prev_votes = None
        assert not block_builder.prev_votes
        assert not block_builder.prev_votes_hash

        prev_votes_hash = block_builder.build_prev_votes_hash()

        assert prev_votes_hash == Hash32.empty()

    # ----- LogsBloom
    @pytest.mark.parametrize("tx_version", tx_versions)
    def test_build_logs_bloom_with_logs_bloom_in_receipt(self, block_builder, tx_factory, tx_version):
        dummy_receipts = {}
        for _ in range(5):
            tx: Transaction = tx_factory(tx_version=tx_version)
            block_builder.transactions[tx.hash] = tx

            dummy_receipts[tx.hash.hex()] = {
                "dummy_receipt": "dummy",
                "logsBloom": BloomFilter.new().hex_0x()
            }
        block_builder.receipts = dummy_receipts

        assert block_builder.receipts
        assert not block_builder.logs_bloom

        logs_bloom = block_builder.build_logs_bloom()

        assert logs_bloom == block_builder.logs_bloom

    @pytest.mark.parametrize("tx_version", tx_versions)
    def test_build_logs_bloom_without_logs_bloom_in_receipt(self, block_builder, tx_factory, tx_version):
        dummy_receipts = {}
        for _ in range(5):
            tx: Transaction = tx_factory(tx_version=tx_version)
            block_builder.transactions[tx.hash] = tx
            dummy_receipts[tx.hash.hex()] = {
                "dummy_receipt": "dummy"
            }
        block_builder.receipts = dummy_receipts

        assert block_builder.receipts
        assert not block_builder.logs_bloom

        logs_bloom = block_builder.build_logs_bloom()

        assert logs_bloom == block_builder.logs_bloom

    def test_build_logs_bloom_returns_its_data_if_exists(self, block_builder):
        expected_logs_bloom = BloomFilter(os.urandom(BloomFilter.size))
        block_builder.logs_bloom = expected_logs_bloom

        logs_bloom = block_builder.build_logs_bloom()

        assert logs_bloom == expected_logs_bloom

    def test_build_logs_bloom_sets_empty_its_if_receipts_not_exists(self, block_builder):
        assert not block_builder.receipts
        assert not block_builder.logs_bloom

        logs_bloom = block_builder.build_logs_bloom()

        assert logs_bloom == BloomFilter.empty()

    # ----- Build Hash
    def test_build_hash(self, block_builder):
        assert not block_builder.hash

        hash_ = block_builder.build_hash()

        assert block_builder.hash
        assert hash_ == block_builder.hash

    def test_build_hash_returns_its_hash_if_exists(self, block_builder):
        expected_hash = Hash32(os.urandom(Hash32.size))
        block_builder.hash = expected_hash

        hash_ = block_builder.build_hash()

        assert hash_ == expected_hash

    def test_build_hash_set_timestamp_as_fixed_timestamp_if_exists(self, block_builder):
        assert not block_builder._timestamp

        expected_timestamp = 1111
        block_builder.fixed_timestamp = expected_timestamp

        block_builder._build_hash()

        assert block_builder._timestamp == expected_timestamp

    def test_build_hash_set_timestamp_as_current_time_if_no_fixed_timestamp(self, block_builder):
        from freezegun import freeze_time
        import datetime

        assert not block_builder.fixed_timestamp
        assert not block_builder._timestamp

        everlasting_time = datetime.datetime(2019, 9, 28, 2, 11, 11, microsecond=123123, tzinfo=datetime.timezone.utc)
        with freeze_time(everlasting_time):
            block_builder._build_hash()

        expected_timestamp = everlasting_time.timestamp()
        timestamp = block_builder._timestamp / 1_000_000

        assert timestamp == expected_timestamp
