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
"""Test Block functions"""

import logging
import random
import unittest
import os
from typing import List

from testcase.unittest import test_util
from loopchain import configure as conf, utils
from loopchain.blockchain import Block, BlockBuilder, BlockVerifier, BlockSerializer, BlockProver, BlockProverType
from loopchain.blockchain import TransactionBuilder, TransactionSerializer, TransactionVersioner
from loopchain.blockchain import Hash32, ExternalAddress
from loopchain.blockchain.exception import TransactionInvalidDuplicatedHash
from loopchain.crypto.signature import Signer
from loopchain.utils import loggers

conf.Configure().init_configure()
loggers.set_preset_type(loggers.PresetType.develop)
loggers.update_preset()


class TestBlock(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signers = [Signer.from_prikey(os.urandom(32)) for _ in range(100)]
        cls.reps: List[ExternalAddress] = [ExternalAddress.fromhex(signer.address) for signer in cls.signers]
        cls.tx_versioner = TransactionVersioner()
        cls.nid = 100

    def setUp(self):
        test_util.print_testname(self._testMethodName)

    def _create_genesis_tx(self):
        tx_builder = TransactionBuilder.new("genesis", self.tx_versioner)
        tx_builder.accounts = [
            {
                "name": "god",
                "address": self.reps[0].hex_hx(),
                "balance": "0xffffffffffffffffffffffffffffffffff"
            }
        ]
        tx_builder.message = "Genesis Transaction"
        tx_builder.nid = self.nid
        return tx_builder.build()

    def _create_v2_tx(self):
        tx_builder = TransactionBuilder.new("0x2", self.tx_versioner)
        tx_builder.private_key = self.signers[0].private_key
        tx_builder.to_address = random.choice(self.reps[1:])
        tx_builder.value = random.randint(1, (10 ** 18) * 100)
        return tx_builder.build()

    def _create_v3_tx(self):
        tx_builder = TransactionBuilder.new("0x3", self.tx_versioner)
        tx_builder.private_key = self.signers[0].private_key
        tx_builder.to_address = random.choice(self.reps[1:])
        tx_builder.value = random.randint(1, (10 ** 18) * 100)
        tx_builder.step_limit = random.randint(100000000, 1000000000000)
        tx_builder.nid = self.nid
        return tx_builder.build()

    def test_block_tx_duplication0(self):
        txs = [self._create_v2_tx() if random.randint(0, 1) % 2 == 0 else self._create_v3_tx()
               for _ in range(random.randint(10, 100))]

        block_builder = BlockBuilder.new("0.1a", self.tx_versioner)
        block_builder.peer_private_key = random.choice(self.signers).private_key
        for tx in txs:
            block_builder.transactions[tx.hash] = tx
        block_builder.height = 10
        block_builder.prev_hash = Hash32(os.urandom(Hash32.size))
        block_builder.next_leader = random.choice(self.signers).private_key
        block_builder.fixed_timestamp = utils.get_now_time_stamp()

        block0 = block_builder.build()
        self.assertIsNotNone(block_builder.hash)
        self.assertIsNotNone(block_builder.merkle_tree_root_hash)
        self.assertEqual(len(block_builder.transactions), len(txs))

        block_builder.reset_cache()
        self.assertIsNone(block_builder.hash)
        self.assertIsNone(block_builder.merkle_tree_root_hash)
        self.assertEqual(len(block_builder.transactions), len(txs))

        # add duplicate txs
        for tx in txs:
            block_builder.transactions[tx.hash] = tx
        block1 = block_builder.build()

        self.assertEqual(block0.body.transactions, block1.body.transactions)
        self.assertEqual(block0.header.merkle_tree_root_hash, block1.header.merkle_tree_root_hash)
        self.assertEqual(block0.header.hash, block1.header.hash)

    def test_block_tx_duplication1(self):
        blockchain = BlockchainMock(self.nid)
        block_builder0 = BlockBuilder.new("0.1a", self.tx_versioner)

        signer_index0 = random.randint(0, len(self.signers) - 1)
        block_builder0.peer_private_key = self.signers[signer_index0].private_key
        block_builder0.height = 0
        block_builder0.prev_hash = None

        signer_index1 = signer_index0 + 1
        signer_index1 %= len(self.signers)
        block_builder0.next_leader = self.reps[signer_index1]

        genesis_tx = self._create_genesis_tx()
        block_builder0.transactions[genesis_tx.hash] = genesis_tx

        block0 = block_builder0.build()
        block_verifier = BlockVerifier.new(block0.header.version, self.tx_versioner)
        block_verifier.verify(block0, None, blockchain, None)
        blockchain.add_block(block0)

        block_builder1 = BlockBuilder.new("0.1a", self.tx_versioner)
        block_builder1.peer_private_key = self.signers[signer_index1].private_key
        block_builder1.height = 1
        block_builder1.prev_hash = block0.header.hash

        signer_index2 = signer_index1 + 1
        signer_index2 %= len(self.signers)
        block_builder1.next_leader = self.reps[signer_index2]

        txv2 = self._create_v2_tx()
        block_builder1.transactions[txv2.hash] = txv2

        block1 = block_builder1.build()
        block_verifier.verify(block1, block0, blockchain, self.reps[signer_index1])
        blockchain.add_block(block1)

        block_builder2 = BlockBuilder.new("0.1a", self.tx_versioner)
        block_builder2.peer_private_key = self.signers[signer_index2].private_key
        block_builder2.height = 2
        block_builder2.prev_hash = block1.header.hash

        signer_index3 = signer_index2 + 1
        signer_index3 %= len(self.signers)
        block_builder2.next_leader = self.reps[signer_index3]

        block_builder2.transactions[txv2.hash] = txv2
        block2 = block_builder2.build()
        self.assertRaises(TransactionInvalidDuplicatedHash,
                          lambda: block_verifier.verify(block2, block1, blockchain, self.reps[signer_index2]))

    def test_block_v0_3(self):
        private_auth = test_util.create_default_peer_auth()
        tx_versioner = TransactionVersioner()

        dummy_receipts = {}
        block_builder = BlockBuilder.new("0.3", tx_versioner)
        for i in range(1000):
            tx_builder = TransactionBuilder.new("0x3", tx_versioner)
            tx_builder.private_key = private_auth.private_key
            tx_builder.to_address = ExternalAddress.new()
            tx_builder.step_limit = random.randint(0, 10000)
            tx_builder.value = random.randint(0, 10000)
            tx_builder.nid = 2
            tx = tx_builder.build()

            tx_serializer = TransactionSerializer.new(tx.version, tx_versioner)
            block_builder.transactions[tx.hash] = tx
            dummy_receipts[tx.hash.hex()] = {
                "dummy_receipt": "dummy",
                "tx_dumped": tx_serializer.to_full_data(tx)
            }

        block_builder.peer_private_key = private_auth.private_key
        block_builder.height = 0
        block_builder.state_hash = Hash32(bytes(Hash32.size))
        block_builder.receipts = dummy_receipts
        block_builder.reps = [ExternalAddress.fromhex_address(private_auth.address)]
        block_builder.next_leader = ExternalAddress.fromhex("hx00112233445566778899aabbccddeeff00112233")

        block = block_builder.build()
        block_verifier = BlockVerifier.new("0.3", tx_versioner)
        block_verifier.invoke_func = lambda b: (block, dummy_receipts)
        block_verifier.verify(block, None, None, block.header.peer_id, reps=block_builder.reps)

        block_serializer = BlockSerializer.new("0.3", tx_versioner)
        block_serialized = block_serializer.serialize(block)
        block_deserialized = block_serializer.deserialize(block_serialized)

        assert block.header == block_deserialized.header
        # FIXME : confirm_prev_block not serialized
        # assert block.body == block_deserialized.body

        tx_hashes = list(block.body.transactions)
        tx_index = random.randrange(0, len(tx_hashes))

        block_prover = BlockProver.new(block.header.version, tx_hashes, BlockProverType.Transaction)
        tx_proof = block_prover.get_proof(tx_index)
        assert block_prover.prove(tx_hashes[tx_index], block.header.transaction_hash, tx_proof)

        block_prover = BlockProver.new(block.header.version, block_builder.receipts, BlockProverType.Receipt)
        receipt_proof = block_prover.get_proof(tx_index)
        receipt_hash = block_prover.to_hash32(block_builder.receipts[tx_index])
        assert block_prover.prove(receipt_hash, block.header.receipt_hash, receipt_proof)


class BlockchainMock:
    def __init__(self, nid):
        self.nid = nid
        self.last_block = None
        self.block_db = {}
        self.tx_db = {}

    @property
    def block_height(self):
        return self.last_block.header.height if self.last_block else -1

    def add_block(self, block: Block):
        self.block_db[block.header.hash] = block
        self.tx_db.update(block.body.transactions)
        self.last_block = block

    def find_nid(self):
        return self.nid

    def find_tx_by_key(self, tx_hash: str):
        try:
            return self.tx_db[Hash32.fromhex(tx_hash, ignore_prefix=True)]
        except KeyError:
            return None
