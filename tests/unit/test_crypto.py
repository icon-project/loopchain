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
"""Test Crypto functions"""

import base64
import copy
import datetime
import hashlib
import json
import logging
import unittest

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.x509.oid import NameOID

from loopchain.utils import loggers
from loopchain.blockchain.types import Hash32
from loopchain.blockchain.transactions import TransactionSerializer, TransactionVersioner
from loopchain.crypto.hashing import build_hash_generator

import tests.unit.test_util as test_util

loggers.set_preset_type(loggers.PresetType.develop)
loggers.update_preset()


class TestCrypto(unittest.TestCase):

    def setUp(self):
        test_util.print_testname(self._testMethodName)

        self.hash_generator = build_hash_generator(1, "icx_sendTransaction")

    def tearDown(self):
        pass

    def test_hash_origin_case_v2(self):
        request = r'''{
            "jsonrpc": "2.0",
            "method": "icx_sendTransaction",
            "id": 1234,
            "params": {
                "from": "hxbe258ceb872e08851f1f59694dac2558708ece11",
                "to": "hx5bfdb090f43a808005ffc27c25b213145e80b7cd",
                "value": "0xde0b6b3a7640000",
                "fee": "0x1000000",
                "timestamp": "1000000000000",
                "nonce": "0x1",
                "tx_hash": "a247a97a23398daccb66e2d61d63788b3c2edb91e1fdbb4f34d86d485eb72915",
                "signature": "VAia7YZ2Ji6igKWzjR2YsGa2m53nKPrfK7uXYW78QLE+ATehAVZPC40szvAiA6NEU5gCYB4c4qaQzqDh2ugcHgA="
            }
        }'''

        logging.info(f"request : {request}")
        request = json.loads(request)
        logging.info(f"request loaded : {request}")

        question = request["params"]
        answer = "icx_sendTransaction.fee.0x1000000.from.hxbe258ceb872e08851f1f59694dac2558708ece11.nonce.0x1." \
                 "timestamp.1000000000000.to.hx5bfdb090f43a808005ffc27c25b213145e80b7cd." \
                 "value.0xde0b6b3a7640000"

        tv = TransactionVersioner()
        version, type_ = tv.get_version(question)
        ts = TransactionSerializer.new(version, type_, tv)
        tx = ts.from_(question)

        result = self.hash_generator.generate_salted_origin(ts.to_origin_data(tx))
        self.assertEqual(result, answer)

    def test_hash_origin_case_v3(self):
        request = '''{
            "jsonrpc": "2.0",
            "method": "icx_sendTransaction",
            "id": 1234,
            "params": {
                "version": "0x3",
                "from": "hxbe258ceb872e08851f1f59694dac2558708ece11",
                "to": "cxb0776ee37f5b45bfaea8cff1d8232fbb6122ec32",
                "stepLimit": "0x12345",
                "timestamp": "0x563a6cf330136",
                "nonce": "0x1",
                "nid": "0x2",
                "signature": "VAia7YZ2Ji6igKWzjR2YsGa2m53nKPrfK7uXYW78QLE+ATehAVZPC40szvAiA6NEU5gCYB4c4qaQzqDh2ugcHgA=",
                "dataType": "call",
                "data": {
                    "method": "transfer",
                    "params": {
                        "to": "hxab2d8215eab14bc6bdd8bfb2c8151257032ecd8b",
                        "value": "0x1",
                        "array0": [
                            "1",
                            "221"
                        ],
                        "array1": [
                            {
                                "hash": "0x12",
                                "value": "0x34"
                            },
                            {
                                "hash": "0x56",
                                "value": "0x78"
                            }
                        ]
                    }
                }
            }
        }'''

        logging.info(f"request : {request}")
        request = json.loads(request)
        logging.info(f"request loaded : {request}")

        question = request["params"]
        answer = "icx_sendTransaction.data.{method.transfer.params." \
                 "{array0.[1.221].array1.[{hash.0x12.value.0x34}.{hash.0x56.value.0x78}]." \
                 "to.hxab2d8215eab14bc6bdd8bfb2c8151257032ecd8b.value.0x1}}." \
                 "dataType.call.from.hxbe258ceb872e08851f1f59694dac2558708ece11.nid.0x2.nonce.0x1.stepLimit.0x12345." \
                 "timestamp.0x563a6cf330136.to.cxb0776ee37f5b45bfaea8cff1d8232fbb6122ec32.version.0x3"

        tv = TransactionVersioner()
        version, type_ = tv.get_version(question)
        ts = TransactionSerializer.new(version, type_, tv)
        tx = ts.from_(question)
        result = self.hash_generator.generate_salted_origin(ts.to_origin_data(tx))
        self.assertEqual(result, answer)

    def test_hash_case_v3_escape(self):
        request = r'''{
            "jsonrpc": "2.0",
            "method": "icx_sendTransaction",
            "id": 1234,
            "params": {
                "version": "0x3",
                "from": "hxbe258ceb872e08851f1f59694dac2558708ece11",
                "to": "cxb0776ee37f5b45bfaea8cff1d8232fbb6122ec32",
                "stepLimit": "0x12345",
                "timestamp": "0x563a6cf330136",
                "nonce": "0x1",
                "nid": "0x2",
                "signature": "VAia7YZ2Ji6igKWzjR2YsGa2m53nKPrfK7uXYW78QLE+ATehAVZPC40szvAiA6NEU5gCYB4c4qaQzqDh2ugcHgA=",
                "dataType": "call",
                "data": {
                    "method": "transfer",
                    "params": {
                        "to": "hx.ab2d8215eab\\14bc6bdd8bfb2c[8151257]032ec{d8}b",
                        "value": "0x1",
                        "array0": [
                            "1",
                            "2.21"
                        ],
                        "array1": [
                            {
                                "hash": "0x12",
                                "value": "0x34"
                            },
                            {
                                "hash": "0x56",
                                "value": "0x78"
                            }
                        ]
                    }
                }
            }
        }'''

        logging.info(f"request : {request}")
        request = json.loads(request)
        logging.info(f"request loaded : {request}")
        logging.info(f"to : {request['params']['data']['params']['to']}")

        question = request['params']
        answer = r"icx_sendTransaction.data.{method.transfer.params." \
                 r"{array0.[1.2\.21].array1.[{hash.0x12.value.0x34}.{hash.0x56.value.0x78}]." \
                 r"to.hx\.ab2d8215eab\\14bc6bdd8bfb2c\[8151257\]032ec\{d8\}b.value.0x1}}." \
                 r"dataType.call.from.hxbe258ceb872e08851f1f59694dac2558708ece11.nid.0x2.nonce.0x1.stepLimit.0x12345." \
                 r"timestamp.0x563a6cf330136.to.cxb0776ee37f5b45bfaea8cff1d8232fbb6122ec32.version.0x3"

        tv = TransactionVersioner()
        version, type_ = tv.get_version(question)
        ts = TransactionSerializer.new(version, type_, tv)
        tx = ts.from_(question)
        result = self.hash_generator.generate_salted_origin(ts.to_origin_data(tx))
        logging.info(f"result : {result}")
        self.assertEqual(result, answer)

    def test_hash_case_v3_null(self):
        request = r'''{
            "jsonrpc": "2.0",
            "method": "icx_sendTransaction",
            "id": 1234,
            "params": {
                "version": "0x3",
                "from": "hxbe258ceb872e08851f1f59694dac2558708ece11",
                "to": "cxb0776ee37f5b45bfaea8cff1d8232fbb6122ec32",
                "stepLimit": "0x12345",
                "timestamp": "0x563a6cf330136",
                "nid": "0x1",
                "nonce": "0x1",
                "signature": "VAia7YZ2Ji6igKWzjR2YsGa2m53nKPrfK7uXYW78QLE+ATehAVZPC40szvAiA6NEU5gCYB4c4qaQzqDh2ugcHgA=",
                "dataType": "call",
                "data": {
                    "method": "transfer",
                    "params": {
                        "to": "hxab2d8215eab14bc6bdd8bfb2c8151257032ecd8b",
                        "value": "0x1",
                        "array0": [
                            null,
                            null
                        ],
                        "array1": [
                            {
                                "hash": null,
                                "value": null
                            },
                            {
                                "hash": null,
                                "value": "0x78"
                            }
                        ]
                    }
                }
            }
        }'''

        logging.info(f"request : {request}")
        request = json.loads(request)
        logging.info(f"request loaded : {request}")

        question = request["params"]
        answer = r"icx_sendTransaction.data.{method.transfer.params." \
                 r"{array0.[\0.\0].array1.[{hash.\0.value.\0}.{hash.\0.value.0x78}]." \
                 r"to.hxab2d8215eab14bc6bdd8bfb2c8151257032ecd8b.value.0x1}}." \
                 r"dataType.call.from.hxbe258ceb872e08851f1f59694dac2558708ece11.nid.0x1.nonce.0x1.stepLimit.0x12345." \
                 r"timestamp.0x563a6cf330136.to.cxb0776ee37f5b45bfaea8cff1d8232fbb6122ec32.version.0x3"

        tv = TransactionVersioner()
        version, type_ = tv.get_version(question)

        ts = TransactionSerializer.new(version, type_, tv)
        tx = ts.from_(question)

        result = self.hash_generator.generate_salted_origin(ts.to_origin_data(tx))
        logging.info(f"result : {result}")
        self.assertEqual(result, answer)

    def test_hash_case_v2_v3_compatibility(self):

        # These methods are obsolete.
        # But this one and new one must have same results for v2 request.
        def create_origin_for_hash(json_data: dict):
            def gen_origin_str(json_data: dict):
                ordered_keys = list(json_data)
                ordered_keys.sort()
                for key in ordered_keys:
                    yield key
                    if isinstance(json_data[key], str):
                        yield json_data[key]
                    elif isinstance(json_data[key], dict):
                        yield from gen_origin_str(json_data[key])
                    elif isinstance(json_data[key], int):
                        yield str(json_data[key])
                    else:
                        raise TypeError(f"{key} must be one of them(dict, str, int).")

            origin = ".".join(gen_origin_str(json_data))
            return origin

        def generate_icx_hash(icx_origin_data, tx_hash_key):
            copy_tx = copy.deepcopy(icx_origin_data)
            if 'method' in copy_tx:
                del copy_tx['method']
            if 'signature' in copy_tx:
                del copy_tx['signature']
            if tx_hash_key in copy_tx:
                del copy_tx[tx_hash_key]
            origin = create_origin_for_hash(copy_tx)
            origin = f"icx_sendTransaction.{origin}"
            # gen hash
            return hashlib.sha3_256(origin.encode()).digest()

        request = r'''{
            "jsonrpc": "2.0",
            "method": "icx_sendTransaction",
            "id": 1234,
            "params": {
                "version": "0x3",
                "from": "hxbe258ceb872e08851f1f59694dac2558708ece11",
                "to": "hx5bfdb090f43a808005ffc27c25b213145e80b7cd",
                "value": "0xde0b6b3a7640000",
                "timestamp": "0x563a6cf330136",
                "nonce": "0x1",
                "stepLimit": "0x100000",
                "nid": "0x2",
                "signature": "VAia7YZ2Ji6igKWzjR2YsGa2m53nKPrfK7uXYW78QLE+ATehAVZPC40szvAiA6NEU5gCYB4c4qaQzqDh2ugcHgA="
            }
        }'''

        logging.info(f"request : {request}")
        request = json.loads(request)
        logging.info(f"request loaded : {request}")

        question = request["params"]

        tv = TransactionVersioner()
        version, type_ = tv.get_version(question)
        ts = TransactionSerializer.new(version, type_, tv)
        tx = ts.from_(question)

        result_new_hash = self.hash_generator.generate_hash(ts.to_origin_data(tx))
        result_old_hash = generate_icx_hash(question, "tx_hash")
        self.assertEqual(result_new_hash, result_old_hash)

        v0_hash_generator = build_hash_generator(0, "icx_sendTransaction")
        result_old_hash = v0_hash_generator.generate_hash(ts.to_origin_data(tx))

        self.assertEquals(result_new_hash, result_old_hash)

    def test_genesis_hash_compatibility(self):
        genesis_init_data = {
            "transaction_data": {
                "accounts": [
                    {
                        "name": "god",
                        "address": "hxebf3a409845cd09dcb5af31ed5be5e34e2af9433",
                        "balance": "0x2961ffa20dd47f5c4700000"
                    },
                    {
                        "name": "treasury",
                        "address": "hxd5775948cb745525d28ec8c1f0c84d73b38c78d4",
                        "balance": "0x0"
                    },
                    {
                        "name": "test1",
                        "address": "hx670e692ffd3d5587c36c3a9d8442f6d2a8fcc795",
                        "balance": "0x0"
                    },
                    {
                        "name": "test2",
                        "address": "hxdc8d79453ba6516bc140b7f53b6b9a012da7ff10",
                        "balance": "0x0"
                    },
                    {
                        "name": "test3",
                        "address": "hxbedeeadea922dc7f196e22eaa763fb01aab0b64c",
                        "balance": "0x0"
                    },
                    {
                        "name": "test4",
                        "address": "hxa88d8addc6495e4c21b0dda5b0bf6c9108c98da6",
                        "balance": "0x0"
                    },
                    {
                        "name": "test5",
                        "address": "hx0260cc5b8777485b04e9dc938b1ee949910f41e1",
                        "balance": "0x0"
                    },
                    {
                        "name": "test6",
                        "address": "hx09e89b468a1cdfdd24441668204911502fa3add9",
                        "balance": "0x0"
                    },
                    {
                        "name": "test7",
                        "address": "hxeacd884f0e0b5b2e4a6b4ee87fa5184ab9f25cbe",
                        "balance": "0x0"
                    },
                    {
                        "name": "test8",
                        "address": "hxa943122f57c7c2af7416c1f2e1af46838ad0958f",
                        "balance": "0x0"
                    },
                    {
                        "name": "test9",
                        "address": "hxc0519e1c56030be070afc89fbf05783c89b15e2f",
                        "balance": "0x0"
                    },
                    {
                        "name": "test10",
                        "address": "hxcebc788d5b922b356a1dccadc384d36964e87165",
                        "balance": "0x0"
                    },
                    {
                        "name": "test11",
                        "address": "hx7f8f432ffdb5fc1d2df6dd452ca52eb719150f3c",
                        "balance": "0x0"
                    },
                    {
                        "name": "test12",
                        "address": "hxa6c4468032824092ecdb3de2bb66947d69e07b59",
                        "balance": "0x0"
                    },
                    {
                        "name": "test13",
                        "address": "hxc26d0b28b11732b38c0a2c0634283730258f272a",
                        "balance": "0x0"
                    },
                    {
                        "name": "test14",
                        "address": "hx695ddb2d1e78f012e3e271e95ffbe4cc8fcd133b",
                        "balance": "0x0"
                    },
                    {
                        "name": "test15",
                        "address": "hx80ab6b11b5d5c80448d011d10fb1a579c57e0a6c",
                        "balance": "0x0"
                    },
                    {
                        "name": "test16",
                        "address": "hxa9c7881a53f2245ed12238412940c6f54874c4e3",
                        "balance": "0x0"
                    },
                    {
                        "name": "test17",
                        "address": "hx4e53cffe116baaff5e1940a6a0c14ad54f7534f2",
                        "balance": "0x0"
                    },
                    {
                        "name": "test18",
                        "address": "hxbbef9e3942d3d5d83b5293b3cbc20940b459e3eb",
                        "balance": "0x0"
                    }
                ],
                "message": "A rHizomE has no beGInning Or enD; it is alWays IN the miDDle, between tHings, interbeing, intermeZzO. ThE tree is fiLiatioN, but the rhizome is alliance, uniquelY alliance. The tree imposes the verb \"to be\" but the fabric of the rhizome is the conJUNction, \"AnD ... and ...and...\"THis conJunction carriEs enouGh force to shaKe and uproot the verb \"to be.\" Where are You goIng? Where are you coMing from? What are you heading for? These are totally useless questions.\n\n- 『Mille Plateaux』, Gilles Deleuze & Felix Guattari\n\n\"Hyperconnect the world\""
            }
        }

        genesis_hash_generator = build_hash_generator(0, "genesis_tx")
        genesis_tx_hash = genesis_hash_generator.generate_hash(genesis_init_data["transaction_data"])
        self.assertEqual(genesis_tx_hash,
                         Hash32.fromhex("0x6dbc389370253739f28b8c236f4e7acdcfcdb9cfe8386c32d809114d5b00ac65"))


if __name__ == '__main__':
    unittest.main()
