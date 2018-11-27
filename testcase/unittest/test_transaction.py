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
from copy import deepcopy
import logging
import time
import unittest
import pickle
import sys
import os

from cryptography import x509
from cryptography.hazmat.backends import default_backend

import testcase.unittest.test_util as test_util
from loopchain.peer import PeerAuthorization
from loopchain import configure as conf
from loopchain.utils import loggers

loggers.set_preset_type(loggers.PresetType.develop)
loggers.update_preset()


@unittest.skip("BVS")
class TestTransaction(unittest.TestCase):

    def setUp(self):
        test_util.print_testname(self._testMethodName)
        self.__origin_channel_option = deepcopy(conf.CHANNEL_OPTION)

    def tearDown(self):

        channel0 = conf.LOOPCHAIN_DEFAULT_CHANNEL
        channel1 = conf.LOOPCHAIN_TEST_CHANNEL

        conf.CHANNEL_OPTION = self.__origin_channel_option

    def test_get_meta_and_put_meta(self):
        # GIVEN
        tx = Transaction()
        tx.put_meta("peer_id", "12345")

        # WHEN
        meta_data = tx.meta
        tx.put_meta("peer_id", "ABCDE")

        # THEN
        logging.debug("tx peer_id(before): " + meta_data["peer_id"])
        logging.debug("tx peer_id(after): " + tx.meta["peer_id"])

        self.assertNotEqual(meta_data["peer_id"], tx.meta["peer_id"])

    def test_put_data(self):
        """트랜잭션 생성확인
        해쉬값의 존재여부

        :return:
        """
        tx = Transaction()
        txhash = tx.put_data("{args:[]}")
        self.assertNotEqual(txhash, "")

    def test_diff_hash(self):
        """트랜잭션을 생성하여, 같은 값을 입력 하여도 트랜잭션 HASH는 달라야 함
        1000건 생성하여 트랜잭션 비교

        :return:
        """
        sttime = time.time()
        tx_list = []
        test_size = 1000
        for x in range(test_size):
            tx1 = Transaction()
            hashed_value = tx1.put_data("{args:[]}")
            tx_list.append(hashed_value)
        self.assertTrue(len(set(tx_list)) == len(tx_list), "중복된 트랜잭션이 있습니다.")
        logging.debug("test_diff_hash %i times : %f", test_size, time.time() - sttime)

    def test_generate_and_validate_hash(self):
        """트랜잭션 생성시 만들어진 hash 와 검증시 비교하는 hash 가 동일한지 확인하는 테스트

        :return:
        """
        # GIVEN
        tx = Transaction()
        tx.init_meta("AAAAA", "BBBBB", "CCCCC", conf.LOOPCHAIN_DEFAULT_CHANNEL, conf.SendTxType.pickle)
        tx.put_meta("1234", "5678")
        tx.put_meta("1", "5")
        tx.put_meta("2", "5")
        tx.put_meta("3", "5")
        tx.put_meta("4", "5")
        txhash1 = tx.put_data("TEST DATA DATA")
        txtime = tx.get_timestamp()

        tx2 = Transaction()
        tx2.init_meta("AAAAA", "BBBBB", "CCCCC", conf.LOOPCHAIN_DEFAULT_CHANNEL, conf.SendTxType.pickle)
        tx2.put_meta("1234", "5678")
        tx2.put_meta("1", "5")
        tx2.put_meta("2", "5")
        tx2.put_meta("3", "5")
        tx2.put_meta("4", "5")
        txhash2 = tx2.put_data("TEST DATA DATA", txtime)

        # WHEN
        txhash1_1 = Transaction.generate_transaction_hash(tx)

        # THEN
        logging.debug("txhash1: " + str(txhash1))
        logging.debug("txhash1_1: " + str(txhash1_1))
        logging.debug("txhash2: " + str(txhash2))

        self.assertEqual(txhash1, txhash2)
        self.assertEqual(txhash1, txhash1_1)
        self.assertEqual(txhash2, txhash1_1)

    def test_transaction_performace(self):
        """트랜잭션의 생성 퍼포먼스 1초에 몇개까지 만들 수 있는지 확인
        1초에 5000개 이상

        :return:
        """
        _sttime = time.time()
        tx_list = []

        dummy_data = "TEST Transaction Data"
        put_data = 0
        while time.time() - _sttime < 1.0:
            tx1 = Transaction()
            hashed_value = tx1.put_data("{args:[]}" + (dummy_data + str(put_data)))
            tx_list.append(hashed_value)
            put_data += 1

        self.assertTrue(len(set(tx_list)) == len(tx_list), "중복된 트랜잭션이 있습니다.")
        logging.debug("TX generate %i in a second", len(tx_list))

        self.assertTrue(len(tx_list) > 5000, len(tx_list))

    def test_dump_tx_size(self):
        # GIVEN
        tx = Transaction()
        tx.put_data("TEST")
        tx.transaction_type = TransactionStatus.confirmed

        tx_only_data = TransactionDataOnly()
        tx_only_data.data = "TEST"

        # WHEN
        dump_a = pickle.dumps(tx_only_data)
        dump_b = pickle.dumps(tx)

        # THEN
        logging.debug("size of tx_only_data: " + str(sys.getsizeof(dump_a)))
        logging.debug("size of tx: " + str(sys.getsizeof(dump_b)))

        self.assertLessEqual(sys.getsizeof(dump_a), sys.getsizeof(dump_b) * 1.5)

    def test_signature_validate(self):
        """GIVEN success tx, invalid public key tx, invalid signature tx,
        WHEN validate 3 tx
        THEN only success tx validate return true
        """
        # GIVEN
        # init peer_auth for signautre

        channel =  list(conf.CHANNEL_OPTION)[0]
        peer_auth = PeerAuthorization(channel=channel)

        # create txs
        success_tx = test_util.create_basic_tx("aaa", peer_auth)

        # public key and signature property must don't have setter
        invalid_public_tx = test_util.create_basic_tx("aaa", peer_auth)
        invalid_public_tx._Transaction__public_key = b'invalid_public'

        invalid_sign_tx = test_util.create_basic_tx("aaa", peer_auth)
        invalid_sign_tx._Transaction__signature = b'invalid_sign'

        hash_generator = get_tx_hash_generator(channel)
        tx_validator = TxValidator(channel, conf.CHANNEL_OPTION[channel]["send_tx_type"], hash_generator)
        # WHEN THEN
        self.assertTrue(tx_validator.validate(success_tx))
        logging.debug("start validate invalid public key")
        self.assertFalse(tx_validator.validate(invalid_public_tx))
        logging.debug("start validate invalid signature")
        self.assertFalse(tx_validator.validate(invalid_sign_tx))

    def test_cert_signature(self):
        """GIVEN conf.TX_CERT_AUTH = True, PeerAuthorization create using cert
        WHEN create new tx and create signature
        THEN tx.public_key must be x.509 der cert
        """
        channel_name = "cert_channel"
        conf.CHANNEL_OPTION = {
            channel_name: {
                "load_cert": True,
                "consensus_cert_use": True,
                "tx_cert_use": True,
                "key_load_type": conf.KeyLoadType.FILE_LOAD,
                "public_path": os.path.join(conf.LOOPCHAIN_ROOT_PATH, 'resources/default_certs/cert.pem'),
                "private_path": os.path.join(conf.LOOPCHAIN_ROOT_PATH, 'resources/default_certs/key.pem'),
                "private_password": None
            }
        }
        peer_auth = PeerAuthorization(channel_name)

        # WHEN
        tx = Transaction()
        tx.put_data('{"a":"b"}')
        tx.sign_hash(peer_auth)

        # THEN
        logging.debug(f"tx public key : {tx.public_key}")
        self.assertEqual(tx.public_key, peer_auth.tx_cert)
        # tx.publickey using for load certificate and not raise any error
        x509.load_der_x509_certificate(tx.public_key, default_backend())


if __name__ == '__main__':
    unittest.main()
