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
"""Validate Strategy for Tx and Signature"""

import abc
import binascii
import hashlib
import json
import logging
import pickle
import re
import traceback
from secp256k1 import PrivateKey, PublicKey

import loopchain.utils as util
from loopchain import configure as conf
from loopchain.blockchain import Transaction
from loopchain.blockchain.exception import *
from loopchain.channel.channel_property import ChannelProperty
from loopchain.protos import loopchain_pb2
from loopchain.tools.signature_helper import PublicVerifierContainer
from .. import HashGenerator


class TxValidateStrategy(metaclass=abc.ABCMeta):
    @staticmethod
    def create(send_tx_type, hash_generator: HashGenerator):
        if send_tx_type == conf.SendTxType.pickle:
            return PickleValidateStrategy(hash_generator)
        elif send_tx_type == conf.SendTxType.json:
            return JsonValidateStrategy(hash_generator)
        elif send_tx_type == conf.SendTxType.icx:
            return IconValidateStrategy(hash_generator)
        else:
            raise Exception

    def __init__(self, hash_generator:HashGenerator):
        self.hash_generator = hash_generator

    @abc.abstractmethod
    def validate(self, tx: Transaction) -> bool:
        pass

    @abc.abstractmethod
    def validate_dumped_tx_message(self, tx_dumped, channel) -> Transaction:
        pass

    @abc.abstractmethod
    def validate_dumped_tx(self, tx_dumped: dict, channel):
        pass

    @abc.abstractmethod
    def restore(self, tx_dumped: str, channel):
        pass

    @abc.abstractmethod
    def load_dumped_tx(self, tx_message: loopchain_pb2.TxSend):
        pass


class IconValidateStrategy(TxValidateStrategy):
    __pri = PrivateKey()
    __ctx_cached = __pri.ctx

    SEND_TX = "icx_sendTransaction"

    def validate_dumped_tx_message(self, tx_json, channel):
        tx = self.restore(tx_json, channel)
        self.validate(tx)
        return tx

    def validate(self, tx: Transaction):
        self.__validate_icx_params(tx.icx_origin_data, tx.tx_hash)
        self.__validate_icx_signature(tx.tx_hash, tx.signature, tx.icx_origin_data['from'])
        return True

    def validate_dumped_tx(self, tx_json: dict, channel):
        return self.validate_dumped_tx_message(json.dumps(tx_json), channel)

    def restore(self, tx_json: str, channel):
        tx = Transaction()
        tx.put_meta(Transaction.SEND_TX_TYPE_KEY, conf.SendTxType.icx)
        tx.put_meta(Transaction.CHANNEL_KEY, channel)
        tx.put_meta(Transaction.METHOD_KEY, self.SEND_TX)
        self.__init_icx_tx(tx_json, tx)
        return tx

    def load_dumped_tx(self, tx_message: loopchain_pb2.TxSend):
        return tx_message.tx_json

    def __init_icx_tx(self, icx_dumped_data: str, tx: Transaction):
        icx_origin_data = json.loads(icx_dumped_data)
        tx.set_icx_origin_data(icx_origin_data, icx_dumped_data)

    def __validate_icx_params(self, icx_origin_data, tx_hash):
        if not util.is_hex(tx_hash):
            raise TransactionInvalidHashForamtError(tx_hash)
        if not self.__is_address(icx_origin_data['from']):
            raise TransactionInvalidAddressError(tx_hash, icx_origin_data['from'], "from addrees is invalid.")

        try:
            expect_tx_hash = self.hash_generator.generate_hash(icx_origin_data)
        except BaseException:
            raise TransactionInvalidHashGenerationError(tx_hash, icx_origin_data)

        if tx_hash != expect_tx_hash:
            logging.info(f"tx tx_hash validate fail expect : {expect_tx_hash} input : {tx_hash}")
            raise TransactionInvalidHashNotMatchError(tx_hash, expect_tx_hash)

        version = icx_origin_data.get("version", None)
        if version is not None and version == hex(conf.ApiVersion.v3):
            nid = icx_origin_data.get("nid", None)
            if nid is None or nid != ChannelProperty().nid:
                raise TransactionInvalidNoNidError(tx_hash, nid, ChannelProperty().nid)

        return True

    def __validate_icx_signature(self, tx_hash, signature, address) -> bool:
        """

        :param tx_hash:
        :param signature:
        :param address:
        :return:
        """
        try:
            origin_signature, recover_code = signature[:-1], signature[-1]
            recoverable_sig = self.__pri.ecdsa_recoverable_deserialize(origin_signature, recover_code)
            pub = self.__pri.ecdsa_recover(binascii.unhexlify(tx_hash),
                                           recover_sig=recoverable_sig,
                                           raw=True,
                                           digest=hashlib.sha3_256)

            public_key = PublicKey(pub, ctx=self.__ctx_cached)
            hash_pub = hashlib.sha3_256(public_key.serialize(compressed=False)[1:]).hexdigest()
            expect_address = f"hx{hash_pub[-40:]}"
            if expect_address != address:
                logging.info(f"tx address validate fail expect : {expect_address} input : {address}")
                raise TransactionInvalidAddressNotMatchError(tx_hash, address, expect_address)
            return True
        except TransactionInvalidAddressNotMatchError as e:
            raise e

        except Exception as e:
            logging.error(f"tx signature validate fail cause {e}")
            traceback.print_exc()
            raise TransactionInvalidSignatureError(tx_hash, signature, address)

    def __is_address(self, address) -> bool:
        if address[:2] != 'hx':
            logging.info(f"address {address} must have header hx")
            return False
        if re.fullmatch(r"^[0-9a-f]{40}$", address[2:] or "") is None:
            logging.info(f"address {address} address contents data must have : ")
            return False
        return True


class PickleValidateStrategy(TxValidateStrategy):
    def validate_dumped_tx(self, tx_pickle: dict, channel):
        pass

    def validate_dumped_tx_message(self, tx_pickle, channel):
        try:
            tx = self.restore(tx_pickle, channel)
            if self.validate(tx):
                return tx
            return None
        except Exception as e:
            logging.debug(f"tx validate fail cause {e}")
            traceback.print_exc()
            return None

    def validate(self, tx: Transaction):
        try:
            if Transaction.generate_transaction_hash(tx) != tx.tx_hash:
                self.__logging_tx_validate("hash validate fail", tx)
                return False

            # tx = self.__tx_validator()

            # Get Cert Verifier for signature verify
            public_verifier = PublicVerifierContainer.get_public_verifier(tx.meta[Transaction.CHANNEL_KEY],
                                                                          tx.public_key)

            # Signature Validate
            if public_verifier.verify_hash(tx.tx_hash, tx.signature):
                return True
            else:
                self.__logging_tx_validate("signature validate fail", tx)
                return False

        except Exception as e:
            self.__logging_tx_validate("signature validate fail", tx)
            return False

    def restore(self, tx_pickle: bytes, channel):
        return pickle.loads(tx_pickle)

    def load_dumped_tx(self, tx_message: loopchain_pb2.TxSend):
        return tx_message.tx

    def __logging_tx_validate(self, fail_message, tx):
        logging.exception(f"validate tx fail "
                          f"\ntx hash : {tx.tx_hash}"
                          f"\ntx meta: {tx.meta}"
                          f"\ntx data: {tx.get_data()}"
                          f"\ntx signature: {tx.signature}"
                          f"\ncaused by: {fail_message}")


class JsonValidateStrategy(TxValidateStrategy):
    def validate_dumped_tx(self, tx_json: dict, channel):
        pass

    def validate_dumped_tx_message(self, tx_json, channel):
        tx = self.restore(tx_json, channel)
        return tx

    def validate(self, tx: Transaction):
        return True

    def restore(self, tx_json: str, channel):
        return Transaction.json_loads(tx_json)

    def load_dumped_tx(self, tx_message: loopchain_pb2.TxSend):
        return tx_message.tx_json
