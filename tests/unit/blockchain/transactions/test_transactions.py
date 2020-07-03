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
"""Test Transaction Functions"""
import os
import random
import unittest
import tests.unit.test_util as test_util
from collections import namedtuple
from loopchain.utils import loggers
from loopchain.blockchain.transactions import TransactionBuilder, TransactionVersioner
from loopchain.blockchain.transactions import TransactionVerifier, TransactionSerializer
from loopchain.blockchain.exception import TransactionInvalidSignatureError, TransactionInvalidNidError
from loopchain.blockchain.exception import TransactionInvalidHashError, TransactionDuplicatedHashError
from loopchain.blockchain.types import ExternalAddress, Signature
from loopchain.crypto.signature import Signer

loggers.set_preset_type(loggers.PresetType.develop)
loggers.update_preset()


class TestTransaction(unittest.TestCase):
    def setUp(self):
        test_util.print_testname(self._testMethodName)
        self.signer = Signer.from_prikey(os.urandom(32))
        self.tx_versioner = TransactionVersioner()
        self.tx_versioner.hash_generator_versions["0x2"] = 0

    def test_transaction_genesis(self):
        tb = TransactionBuilder.new("genesis", None, self.tx_versioner)
        tb.accounts = [
            {
                "name": "test0",
                "address": ExternalAddress(os.urandom(20)).hex_hx(),
                "balance": "0x12221231"
            }
        ]
        tb.message = "Icon Loop"
        tx = tb.build(False)

        tv = TransactionVerifier.new("genesis", tx.type(), self.tx_versioner)
        tv.verify(tx)

        ts = TransactionSerializer.new("genesis", tx.type(), self.tx_versioner)
        tx_raw_data = ts.to_raw_data(tx)

        self.assertEqual(ts.from_(tx_raw_data), tx)

    def test_transaction_v2(self):
        tb = TransactionBuilder.new("0x2", None, self.tx_versioner)
        tb.fee = 1000000
        tb.value = 100000
        tb.signer = self.signer
        tb.to_address = ExternalAddress(os.urandom(20))
        tb.nonce = random.randint(0, 100000)
        tx = tb.build()

        tv = TransactionVerifier.new("0x2", tx.type(), self.tx_versioner)
        tv.verify(tx)

        ts = TransactionSerializer.new("0x2", tx.type(), self.tx_versioner)
        tx_raw_data = ts.to_raw_data(tx)

        self.assertEqual(ts.from_(tx_raw_data), tx)

    def test_transaction_v3(self):
        tb = TransactionBuilder.new("0x3", None, self.tx_versioner)
        tb.step_limit = 1000000
        tb.value = 100000
        tb.signer = self.signer
        tb.to_address = ExternalAddress(os.urandom(20))
        tb.nid = 3
        tb.nonce = random.randint(0, 100000)
        tb.data = "test"
        tb.data_type = "message"
        tx = tb.build()

        tv = TransactionVerifier.new("0x3",  tx.type(), self.tx_versioner)
        tv.verify(tx)

        ts = TransactionSerializer.new("0x3", tx.type(), self.tx_versioner)
        tx_raw_data = ts.to_raw_data(tx)

        self.assertEqual(ts.from_(tx_raw_data), tx)

    def test_transaction_v2_unsigned(self):
        signer = Signer.new()

        tb = TransactionBuilder.new("0x2", None, self.tx_versioner)
        tb.fee = 1000000
        tb.value = 100000
        tb.from_address = ExternalAddress.fromhex_address(signer.address)
        tb.to_address = ExternalAddress(os.urandom(20))
        tb.nonce = random.randint(0, 100000)
        tx = tb.build(is_signing=False)

        tv = TransactionVerifier.new("0x2", tx.type(), self.tx_versioner)
        self.assertRaises(TransactionInvalidSignatureError, lambda: tv.verify(tx))
        self.assertRaises(TransactionInvalidSignatureError, lambda: tv.pre_verify(tx))

        tb.signer = signer
        signed_tx = tb.sign_transaction(tx)
        tv.verify(signed_tx)
        tv.pre_verify(signed_tx)

    def test_transaction_v3_unsigned(self):
        signer = Signer.new()

        tb = TransactionBuilder.new("0x3", None, self.tx_versioner)
        tb.step_limit = 1000000
        tb.value = 100000
        tb.from_address = ExternalAddress.fromhex_address(signer.address)
        tb.to_address = ExternalAddress(os.urandom(20))
        tb.nid = 3
        tb.nonce = random.randint(0, 100000)
        tb.data = "test"
        tb.data_type = "message"
        tx = tb.build(False)

        tv = TransactionVerifier.new("0x3", tx.type(), self.tx_versioner)
        self.assertRaises(TransactionInvalidSignatureError, lambda: tv.verify(tx))
        self.assertRaises(TransactionInvalidSignatureError, lambda: tv.pre_verify(tx, nid=3))

        tb.signer = signer
        signed_tx = tb.sign_transaction(tx)
        tv.verify(signed_tx)
        tv.pre_verify(signed_tx, nid=3)

    def test_transaction_v2_invalid_hash0(self):
        # noinspection PyDictCreation
        tx_dumped = {
            'from': 'hx48cd6eb32339d5c719dcc0af21e9bc3b67d733e6',
            'to': 'hx22f72e44141bedd50d1e536455682863d3d8a484',
            'value': '0x186a0',
            'fee': '0xf4240',
            'timestamp': '1558679280067963',
            'nonce': '1',
            'tx_hash': '34477b3bc76fa73aad0258ba9fd36f28a3c4b26956c1e5eb92ddda7d98df4e32',  # valid hash
            'signature': 'W/hW/PAo+ExeSsreD//yJVgNqmnkWKs+m0VUqE11O7Ek82yEINuczLRXtj1k515q8Ep4OLsRPPiPNjDM9vuhsgE='
        }
        tx_dumped['tx_hash'] = os.urandom(32).hex()  # invalid hash

        tx_version, tx_type = self.tx_versioner.get_version(tx_dumped)
        ts = TransactionSerializer.new(tx_version, tx_type, self.tx_versioner)
        tx = ts.from_(tx_dumped)

        tv = TransactionVerifier.new(tx_version, tx_type, self.tx_versioner)
        self.assertRaises(TransactionInvalidHashError, lambda: tv.verify(tx))
        self.assertRaises(TransactionInvalidHashError, lambda: tv.pre_verify(tx))

    def test_transaction_v2_invalid_hash1(self):
        # noinspection PyDictCreation
        tx_dumped = {
            'from': 'hx48cd6eb32339d5c719dcc0af21e9bc3b67d733e6',
            'to': 'hx22f72e44141bedd50d1e536455682863d3d8a484',
            'value': '0x186a0',
            'fee': '0xf4240',
            'timestamp': '1558679280067963',
            'nonce': '1',
            'tx_hash': '34477b3bc76fa73aad0258ba9fd36f28a3c4b26956c1e5eb92ddda7d98df4e32',
            'signature': 'W/hW/PAo+ExeSsreD//yJVgNqmnkWKs+m0VUqE11O7Ek82yEINuczLRXtj1k515q8Ep4OLsRPPiPNjDM9vuhsgE='
        }
        tx_dumped['value'] = hex(int(random.randrange(1, 100)))  # invalid value

        tx_version, tx_type = self.tx_versioner.get_version(tx_dumped)
        ts = TransactionSerializer.new(tx_version, tx_type, self.tx_versioner)
        tx = ts.from_(tx_dumped)

        tv = TransactionVerifier.new(tx_version, tx_type, self.tx_versioner)
        self.assertRaises(TransactionInvalidHashError, lambda: tv.verify(tx))
        self.assertRaises(TransactionInvalidHashError, lambda: tv.pre_verify(tx))

    def test_transaction_v2_invalid_signature(self):
        # noinspection PyDictCreation
        tx_dumped = {
            'from': 'hx48cd6eb32339d5c719dcc0af21e9bc3b67d733e6',
            'to': 'hx22f72e44141bedd50d1e536455682863d3d8a484',
            'value': '0x186a0',
            'fee': '0xf4240',
            'timestamp': '1558679280067963',
            'nonce': '1',
            'tx_hash': '34477b3bc76fa73aad0258ba9fd36f28a3c4b26956c1e5eb92ddda7d98df4e32',  # valid hash
            'signature': 'W/hW/PAo+ExeSsreD//yJVgNqmnkWKs+m0VUqE11O7Ek82yEINuczLRXtj1k515q8Ep4OLsRPPiPNjDM9vuhsgE='
        }
        tx_dumped['signature'] = Signature(os.urandom(Signature.size)).to_base64str()  # invalid signature

        tx_version, tx_type = self.tx_versioner.get_version(tx_dumped)
        ts = TransactionSerializer.new(tx_version, tx_type, self.tx_versioner)
        tx = ts.from_(tx_dumped)

        tv = TransactionVerifier.new(tx_version, tx_type, self.tx_versioner)
        self.assertRaises(TransactionInvalidSignatureError, lambda: tv.verify(tx))
        self.assertRaises(TransactionInvalidSignatureError, lambda: tv.pre_verify(tx))

    def test_transaction_v3_invalid_signature(self):
        # noinspection PyDictCreation
        tx_dumped = {
            'version': '0x3',
            'from': 'hx48cd6eb32339d5c719dcc0af21e9bc3b67d733e6',
            'to': 'hxe0a231fa5c80e45f51d7df5f7d127954320df829',
            'stepLimit': '0xf4240',
            'timestamp': '0x5899c717f92f8',
            'nid': '0x3',
            'value': '0x186a0',
            'nonce': '0x64',
            'data': 'test',
            'dataType': 'message',
            'signature': 'J84KdBtQR4w1bcBdBGF8g6aNoCXjsY/5T6vGV4RXeMwEvafj9xVRDVjzF+vN1JVYvXrAzjlYPCiiBXBQe6+tRAE='
        }
        tx_dumped['signature'] = Signature(os.urandom(Signature.size)).to_base64str()  # invalid signature

        tx_version, tx_type = self.tx_versioner.get_version(tx_dumped)
        ts = TransactionSerializer.new(tx_version, tx_type, self.tx_versioner)
        tx = ts.from_(tx_dumped)

        tv = TransactionVerifier.new(tx_version, tx_type, self.tx_versioner)
        self.assertRaises(TransactionInvalidSignatureError, lambda: tv.verify(tx))
        self.assertRaises(TransactionInvalidSignatureError, lambda: tv.pre_verify(tx, nid=3))

    def test_transaction_v3_invalid_nid(self):
        MockBlockchain = namedtuple("MockBlockchain", "find_nid find_tx_by_key")
        nids = list(range(0, 1000))
        random.shuffle(nids)

        tb = TransactionBuilder.new("0x3", None, self.tx_versioner)
        tb.step_limit = 1000000
        tb.value = 100000
        tb.signer = self.signer
        tb.to_address = ExternalAddress(os.urandom(20))
        tb.nid = nids[0]
        tb.nonce = random.randint(0, 100000)
        tb.data = "test"
        tb.data_type = "message"
        tx = tb.build()

        expected_nid = nids[1]
        mock_blockchain = MockBlockchain(find_nid=lambda: hex(expected_nid),
                                         find_tx_by_key=lambda _: False)

        tv = TransactionVerifier.new(tx.version, tx.type(), self.tx_versioner)
        self.assertRaises(TransactionInvalidNidError, lambda: tv.verify(tx, mock_blockchain))
        self.assertRaises(TransactionInvalidNidError, lambda: tv.pre_verify(tx, nid=expected_nid))

    def test_transaction_v2_duplicate_hash(self):
        MockBlockchain = namedtuple("MockBlockchain", "find_nid find_tx_by_key")

        tb = TransactionBuilder.new("0x2", None, self.tx_versioner)
        tb.fee = 1000000
        tb.value = 100000
        tb.signer = self.signer
        tb.to_address = ExternalAddress(os.urandom(20))
        tb.nonce = random.randint(0, 100000)
        tx = tb.build()

        mock_blockchain = MockBlockchain(find_nid=lambda: hex(3),
                                         find_tx_by_key=lambda _: True)

        tv = TransactionVerifier.new(tx.version, tx.type(), self.tx_versioner)
        self.assertRaises(TransactionDuplicatedHashError, lambda: tv.verify(tx, mock_blockchain))

    def test_transaction_v3_duplicate_hash(self):
        MockBlockchain = namedtuple("MockBlockchain", "find_nid find_tx_by_key")

        tb = TransactionBuilder.new("0x3", None, self.tx_versioner)
        tb.step_limit = 1000000
        tb.value = 100000
        tb.signer = self.signer
        tb.to_address = ExternalAddress(os.urandom(20))
        tb.nid = 3
        tb.nonce = random.randint(0, 100000)
        tb.data = "test"
        tb.data_type = "message"
        tx = tb.build()

        mock_blockchain = MockBlockchain(find_nid=lambda: hex(3),
                                         find_tx_by_key=lambda _: True)

        tv = TransactionVerifier.new(tx.version, tx.type(), self.tx_versioner)
        self.assertRaises(TransactionDuplicatedHashError, lambda: tv.verify(tx, mock_blockchain))

