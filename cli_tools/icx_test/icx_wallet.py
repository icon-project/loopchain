#!/usr/bin/env python
import base64
import hashlib
import logging
import binascii
import random
import sys

from secp256k1 import PrivateKey, PublicKey
from loopchain import utils, configure as conf
from loopchain.blockchain.hashing import get_tx_hash_generator

ICX_FACTOR = 10 ** 18
ICX_FEE = 0.01


class IcxWallet:
    def __init__(self, private_key=None):
        self.__private_key = private_key or PrivateKey()
        self.__address = self.create_address(self.__private_key.pubkey)
        self.__last_tx_hash = ""
        self.__hash_generator = get_tx_hash_generator(conf.LOOPCHAIN_DEFAULT_CHANNEL)

        self.to_address = None
        self.value = None
        self.message = None
        self.fee = ICX_FEE
        self.nid = '0x3'
        self.is_logging = True

    @property
    def address(self):
        return self.__address

    @property
    def last_tx_hash(self):
        return self.__last_tx_hash

    @last_tx_hash.setter
    def last_tx_hash(self, last_tx_hash):
        self.__last_tx_hash = last_tx_hash

    def create_icx_origin(self, is_raw_data=False):
        params = dict()
        params["from"] = self.address
        params["to"] = self.to_address
        params["value"] = hex(int(self.value * ICX_FACTOR))
        params["fee"] = hex(int(self.fee * ICX_FACTOR))
        params["timestamp"] = str(utils.get_now_time_stamp())

        tx_hash = self.__hash_generator.generate_hash(params)
        params["tx_hash"] = tx_hash
        params["signature"] = self.create_signature(tx_hash)

        icx_origin = dict()
        icx_origin["jsonrpc"] = "2.0"
        icx_origin["method"] = "icx_sendTransaction"
        icx_origin["id"] = random.randrange(0, 100000)
        icx_origin["params"] = params
        self.__last_tx_hash = tx_hash
        print(params)

        return icx_origin if is_raw_data else params

    def create_icx_origin_v3(self, is_raw_data=False):
        params = dict()
        params["version"] = "0x3"
        params["from"] = self.address
        params["to"] = self.to_address
        params["value"] = hex(int(self.value * ICX_FACTOR))
        params["stepLimit"] = "0x3000000"
        params["timestamp"] = hex(utils.get_now_time_stamp())
        params["nonce"] = "0x0"
        params["nid"] = self.nid
        if self.message is not None:
            params["dataType"] = "message"
            params["data"] = self.message.encode('utf-8').hex()

        hash_for_sign = self.__hash_generator.generate_hash(params)
        params["signature"] = self.create_signature(hash_for_sign)

        icx_origin = dict()
        icx_origin["jsonrpc"] = "2.0"
        icx_origin["method"] = "icx_sendTransaction"
        icx_origin["id"] = random.randrange(0, 100000)
        icx_origin["params"] = params

        return icx_origin if is_raw_data else params

    def create_address(self, public_key: PublicKey) -> str:
        serialized_pub = public_key.serialize(compressed=False)
        hashed_pub = hashlib.sha3_256(serialized_pub[1:]).hexdigest()
        return f"hx{hashed_pub[-40:]}"

    def create_signature(self, tx_hash):
        signature = self.__private_key.ecdsa_sign_recoverable(msg=binascii.unhexlify(tx_hash),
                                                              raw=True,
                                                              digest=hashlib.sha3_256)
        serialized_sig = self.__private_key.ecdsa_recoverable_serialize(signature)
        if self.is_logging:
            logging.debug(f"serialized_sig : {serialized_sig} "
                          f"\n not_recover_msg size : {sys.getsizeof(serialized_sig[0])}"
                          f"\n len {len(serialized_sig[0])}")
        sig_message = b''.join([serialized_sig[0], bytes([serialized_sig[1]])])
        if self.is_logging:
            logging.debug(f"sig message :{sig_message} "
                          f"\n with_recover_msg size : {sys.getsizeof(sig_message)}"
                          f"\n len {len(sig_message)}"
                          f"\n {type(sig_message[-1])}")
        signature = base64.b64encode(sig_message).decode()
        return signature
