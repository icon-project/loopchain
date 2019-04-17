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
""" A class for signature verifier of Peer"""

import hashlib
import logging
from abc import ABCMeta, abstractmethod
from collections import namedtuple

from secp256k1 import PrivateKey, PublicKey

from loopchain import utils
from loopchain.blockchain import Signature, ExternalAddress, Address


class SignatureVerifierBase(metaclass=ABCMeta):
    VerifiedAddress = namedtuple("VerifiedAddress", "result expected_address")

    _private_key = PrivateKey()
    address: 'ExternalAddress' = None

    def verify_data(self, origin_data: bytes, signature: Signature):
        return self.verify(origin_data, signature, False)

    def verify_hash(self, origin_data: bytes, signature: Signature):
        return self.verify(origin_data, signature, True)

    @classmethod
    def from_channel_with_public_key(cls, channel: str):
        from loopchain import configure as conf

        public_file = conf.CHANNEL_OPTION[channel]["public_path"]
        return cls.from_pubkey_file(public_file)

    @classmethod
    def from_pubkey_file(cls, pubkey_file: str):
        with open(pubkey_file, "rb") as der:
            pubkey = der.read()
        return cls.from_pubkey(pubkey)

    @classmethod
    def from_pubkey(cls, pubkey: bytes):
        address = ExternalAddress(utils.address_from_pubkey(pubkey))
        return cls.from_address(address.hex_hx())

    @classmethod
    def from_address(cls, address: str):
        verifier = RecoverableSignatureVerifier()
        verifier.address = Address.fromhex_address(address)
        return verifier

    @abstractmethod
    def verify(self, origin_data: bytes, signature: Signature, is_hash: bool):
        raise NotImplementedError


class RecoverableSignatureVerifier(SignatureVerifierBase):
    def __verify_address(self, pubkey: bytes) -> 'VerifiedAddress':
        expected_address = Address(utils.address_from_pubkey(pubkey))
        verified_address = self.VerifiedAddress(expected_address == self.address, expected_address)
        return verified_address

    def verify(self, origin_data: bytes, signature: Signature, is_hash: bool) -> 'VerifiedAddress':
        try:
            if not is_hash:
                origin_data = hashlib.sha3_256(origin_data).digest()

            recoverable_sig = self._private_key.ecdsa_recoverable_deserialize(
                signature.signature(), signature.recover_id())
            pub = self._private_key.ecdsa_recover(origin_data,
                                                  recover_sig=recoverable_sig,
                                                  raw=is_hash,
                                                  digest=hashlib.sha3_256)
            extract_pub = PublicKey(pub).serialize(compressed=False)
            return self.__verify_address(extract_pub)
        except Exception as e:
            logging.debug(f"Fail to verify the signature : ({origin_data})/({signature})\n{e}")
            return self.VerifiedAddress(False, None)


class HSMSignatureVerifier(SignatureVerifierBase):
    def verify(self, origin_data: bytes, signature: Signature, is_hash: bool):
        from cryptography.hazmat.primitives import hashes, asymmetric
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.exceptions import InvalidSignature
        from loopchain.baseservice import ObjectManager

        public_key = ObjectManager().channel_service.peer_manager.get_peer(self.address.hex_hx()).public_key
        hash_algorithm = asymmetric.utils.Prehashed(hashes.SHA256())

        try:
            public_key.verify(signature.signature(), origin_data, ec.ECDSA(hash_algorithm))
            return self.VerifiedAddress(True, None)
        except InvalidSignature:
            raise RuntimeError(f"Invalid Signature in a Block.\n{signature.signature()}")
