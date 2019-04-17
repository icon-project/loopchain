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
"""Test Tx Validator"""
import base64
import hashlib
import json
import logging
import unittest
import time
from typing import Dict

import binascii

import sys

from loopchain.blockchain import NID

from loopchain.channel.channel_property import ChannelProperty
from secp256k1 import PrivateKey, PublicKey

from cli_tools.icx_test.icx_wallet import IcxWallet
import loopchain.utils as util
from loopchain import configure as conf
from loopchain import utils, loggers
from loopchain.blockchain.exception import *

loggers.set_preset_type(loggers.PresetType.develop)
loggers.update_preset()


@unittest.skip("BVS")
class TestTxValidator(unittest.TestCase):
    def setUp(self):
        # create private key and sender_address receive_address
        self.private_key = PrivateKey()
        self.send_address = self.__create_address(self.private_key.pubkey)
        logging.debug(f"create sender address : {self.send_address}")
        self.receive_address = self.__create_address(PrivateKey().pubkey)
        logging.debug(f"create sender address : {self.receive_address}")

        self.hash_generator = get_tx_hash_generator(conf.LOOPCHAIN_DEFAULT_CHANNEL)
        self.tx_validator = TxValidator(conf.LOOPCHAIN_DEFAULT_CHANNEL, conf.SendTxType.icx, self.hash_generator)

    def __create_address(self, public_key: PublicKey) -> str:
        serialized_pub = public_key.serialize(compressed=False)
        hashed_pub = hashlib.sha3_256(serialized_pub[1:]).hexdigest()
        return f'hx{hashed_pub[-40:]}'

    def __create_icx_origin(self):
        icx_origin = dict()
        icx_origin["from"] = self.send_address
        icx_origin["to"] = self.receive_address
        icx_origin["value"] = "0xde0b6b3a7640000"
        icx_origin["fee"] = "0x2386f26fc10000"
        icx_origin["timestamp"] = str(util.get_now_time_stamp())
        icx_origin["nonce"] = "0x3"
        tx_hash = self.__create_hash(icx_origin)
        self.tx_hash = tx_hash
        icx_origin["tx_hash"] = tx_hash
        logging.debug(f"tx_hash : {tx_hash}")
        self.__create_signature_to_origin(icx_origin, tx_hash)

        return icx_origin

    def __create_icx_origin_v3(self):
        icx_origin = dict()
        icx_origin["from"] = self.send_address
        icx_origin["to"] = self.receive_address
        icx_origin["value"] = "0xde0b6b3a7640000"
        icx_origin["fee"] = "0x2386f26fc10000"
        icx_origin["timestamp"] = str(util.get_now_time_stamp())
        icx_origin["nonce"] = "0x3"
        icx_origin["nid"] = NID.testnet.value
        icx_origin["stepLimit"] = "0x12345"
        icx_origin["version"] = "0x3"
        tx_hash = self.__create_hash(icx_origin)
        self.tx_hash = tx_hash
        self.__create_signature_to_origin(icx_origin, tx_hash)

        return icx_origin

    def __create_signature_to_origin(self, icx_origin, tx_hash):
        signature = self.private_key.ecdsa_sign_recoverable(msg=binascii.unhexlify(tx_hash),
                                                            raw=True,
                                                            digest=hashlib.sha3_256)
        serialized_sig = self.private_key.ecdsa_recoverable_serialize(signature)
        logging.debug(f"serialized_sig : {serialized_sig} "
                      f"\n not_recover_msg size : {sys.getsizeof(serialized_sig[0])}")
        sig_message = b''.join([serialized_sig[0], bytes([serialized_sig[1]])])
        logging.debug(f"sig message :{sig_message} "
                      f"\n with_recover_msg size : {sys.getsizeof(sig_message)}")
        icx_origin['signature'] = base64.b64encode(sig_message).decode()

    def __create_hash(self, icx_origin):
        # gen origin
        gen = self.gen_ordered_items(icx_origin)
        origin = ".".join(gen)
        origin = f"icx_sendTransaction.{origin}"
        logging.debug(f"origin data : {origin}")
        logging.debug(f"encode origin : {origin.encode()}")
        # gen hash
        return hashlib.sha3_256(origin.encode()).hexdigest()

    def gen_ordered_items(self, parameter):
        ordered_keys = list(parameter)
        ordered_keys.sort()
        for key in ordered_keys:
            logging.debug(f"item : {key}, {parameter[key]}")
            yield key
            if isinstance(parameter[key], str):
                yield parameter[key]
            elif isinstance(parameter[key], dict):
                yield from self.gen_ordered_items(parameter[key])
            else:
                raise TypeError(f"{key} must be dict or str")

    def test_validate_icx_tx(self):
        """ GIVEN icx transaction that type of string, create TxValidator with sent_tx_type to icx
        WHEN restore tx THEN can create correct tx
        WHEN validate tx_object THEN return true
        :return:
        """

        for i in range(1000):
            icx_origin = self.__create_icx_origin()  # type: Dict[str, str]
            message = json.dumps(icx_origin)
            tx = self.tx_validator.validate_dumped_tx_message(message)
            self.assertEqual(tx.tx_hash, self.tx_hash)
            self.assertEqual(tx.signature, base64.b64decode(icx_origin['signature'].encode()))
            self.assertTrue(self.tx_validator.validate(tx))

    def test_validate_nid_v3(self):
        ChannelProperty().nid = NID.testnet.value
        icx_origin = self.__create_icx_origin_v3()  # type: Dict[str, str]
        message = json.dumps(icx_origin)
        tx = self.tx_validator.validate_dumped_tx_message(message)
        self.assertEqual(tx.icx_origin_data_v3["version"], hex(conf.ApiVersion.v3))
        self.assertEqual(tx.icx_origin_data_v3["nid"], ChannelProperty().nid)
        self.assertTrue(self.tx_validator.validate(tx))
        ChannelProperty().nid = None

    def test_validate_repeat(self):
        """ for validate ctx sharing
        :return:
        """
        for i in range(1000):
            icx_origin = self.__create_icx_origin()  # type: Dict[str, str]
            message = json.dumps(icx_origin)
            tx = self.tx_validator.validate_dumped_tx_message(message)
            self.assertEqual(tx.tx_hash, self.tx_hash)
            self.assertEqual(tx.signature, base64.b64decode(icx_origin['signature'].encode()))
            self.assertTrue(self.tx_validator.validate(tx))

    def test_transaction_invalid_hash_foramt(self):
        wallet = IcxWallet()
        wallet.value = 1

        params = wallet.create_icx_origin()
        params['tx_hash'] = "12312"
        self.__test_wallet_exception(params, TransactionInvalidHashFormatError)

    def test_transaction_invalid_address(self):
        wallet = IcxWallet()
        wallet.value = 1
        wallet._IcxWallet__address = "hx2983"

        params = wallet.create_icx_origin()
        self.__test_wallet_exception(params, TransactionInvalidAddressError)

        params = wallet.create_icx_origin_v3()
        self.__test_wallet_exception(params, TransactionInvalidAddressError)

    def test_transcation_invalid_address_not_match(self):
        wallet = IcxWallet()
        wallet.value = 1

        paramsv2 = wallet.create_icx_origin()
        paramsv3 = wallet.create_icx_origin_v3()

        another_wallet = IcxWallet()

        # sign hash with another wallet's private key
        paramsv2['signature'] = another_wallet.create_signature(self.hash_generator.generate_hash(paramsv2))
        paramsv3['signature'] = another_wallet.create_signature(self.hash_generator.generate_hash(paramsv3))

        logging.info("address: " + wallet.address)
        logging.info("another addres: " + another_wallet.address)

        ChannelProperty().nid = '0x3'

        exception: TransactionInvalidAddressNotMatchError = self.__test_wallet_exception(
            paramsv2, TransactionInvalidAddressNotMatchError)
        self.assertEquals(exception.address, wallet.address)
        self.assertEquals(exception.expected_address, another_wallet.address)

        exception: TransactionInvalidAddressNotMatchError = self.__test_wallet_exception(
            paramsv3, TransactionInvalidAddressNotMatchError)
        self.assertEquals(exception.address, wallet.address)
        self.assertEquals(exception.expected_address, another_wallet.address)

        # These codes below affects hash generation.
        # V3 params does not have `txHash`.
        # So it cannot raise `HashNotMatch` Exception but `AddressNotMatch`
        paramsv3 = wallet.create_icx_origin_v3()
        paramsv3["timestamp"] = hex(utils.get_now_time_stamp())

        exception: TransactionInvalidAddressNotMatchError = self.__test_wallet_exception(
            paramsv3, TransactionInvalidAddressNotMatchError)
        self.assertEquals(exception.address, wallet.address)

    def test_transaction_invalid_hash_not_match(self):
        wallet = IcxWallet()
        wallet.value = 1

        # V3 params does not have `txHash`.
        # So it cannot raise `HashNotMatch` Exception but `AddressNotMatch`
        paramsv2 = wallet.create_icx_origin()

        time.sleep(0.1)
        paramsv2["timestamp"] = str(utils.get_now_time_stamp())

        self.__test_wallet_exception(paramsv2, TransactionInvalidHashNotMatchError)

    def test_transaction_invalid_hash_generation(self):
        wallet = IcxWallet()
        wallet.value = 1

        paramsv2 = wallet.create_icx_origin()

        # make recursion for raising an exception.
        paramsv2['recursion'] = paramsv2

        try:
            icon_validator = IconValidateStrategy(self.hash_generator)
            icon_validator._IconValidateStrategy__validate_icx_params(paramsv2, paramsv2['tx_hash'])
        except TransactionInvalidHashGenerationError as e:
            logging.info(TransactionInvalidHashGenerationError.__name__)
            logging.info(e)
        else:
            raise RuntimeError(f"{TransactionInvalidHashGenerationError.__name__} did not raise.")

    def test_transacion_invalid_signature(self):
        wallet = IcxWallet()
        wallet.value = 1

        paramsv2 = wallet.create_icx_origin()

        try:
            icon_validator = IconValidateStrategy(self.hash_generator)
            icon_validator._IconValidateStrategy__validate_icx_signature(
                paramsv2['tx_hash'], "weds", paramsv2['from'])
        except TransactionInvalidSignatureError as e:
            logging.info(TransactionInvalidSignatureError.__name__)
            logging.info(e)
        else:
            raise RuntimeError(f"{TransactionInvalidSignatureError.__name__} did not raise.")

    def test_transaction_invalid_wrong_nid(self):
        wallet = IcxWallet()
        wallet.value = 1
        wallet.nid = '0x5'

        ChannelProperty().nid = '0x3'

        param3 = wallet.create_icx_origin_v3()

        exception: TransactionInvalidNoNidError = self.__test_wallet_exception(param3, TransactionInvalidNoNidError)
        self.assertEqual(exception.expected_nid, ChannelProperty().nid)
        self.assertEqual(exception.nid, wallet.nid)

    def __test_wallet_exception(self, wallet_params, error_type):
        dumped_params = json.dumps(wallet_params)

        try:
            self.tx_validator.validate_dumped_tx_message(dumped_params)
        except error_type as e:
            logging.info(error_type.__name__)
            logging.info(e)

            return e
        else:
            raise RuntimeError(f"{error_type.__name__} did not raise.")