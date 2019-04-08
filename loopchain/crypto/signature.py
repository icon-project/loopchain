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
""" A class for icx authorization of Peer"""

import binascii
import getpass
import hashlib
import logging

from typing import Union, Callable

from abc import ABCMeta, abstractmethod
from asn1crypto import keys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from secp256k1 import PrivateKey, PublicKey
from yubihsm.objects import AsymmetricKey

from loopchain import utils
from loopchain.blockchain import SignatureFlag, FlaggedHsmSignature, Signature, FlaggedSignature
from loopchain.tools.hsm_helper import HsmHelper


class SignVerifier:
    _pri = PrivateKey()

    def __init__(self):
        self.address: str = None

    def verify_address(self, pubkey: bytes):
        return self.address_from_pubkey(pubkey) == self.address

    def verify_data(self, origin_data: bytes, signature: bytes):
        return self.verify_signature(origin_data, signature, False)

    def verify_hash(self, origin_data, signature):
        return self.verify_signature(origin_data, signature, True)

    def verify_signature(self, origin_data: bytes, signature: bytes, is_hash: bool):
        try:
            if is_hash:
                origin_data = binascii.unhexlify(origin_data)
            origin_signature, recover_code = signature[:-1], signature[-1]
            recoverable_sig = self._pri.ecdsa_recoverable_deserialize(origin_signature, recover_code)
            pub = self._pri.ecdsa_recover(origin_data,
                                          recover_sig=recoverable_sig,
                                          raw=is_hash,
                                          digest=hashlib.sha3_256)
            extract_pub = PublicKey(pub).serialize(compressed=False)
            return self.verify_address(extract_pub)
        except Exception:
            logging.debug(f"signature verify fail : {origin_data} {signature}")
            return False

    @classmethod
    def address_from_pubkey(cls, pubkey: bytes):
        hash_pub = hashlib.sha3_256(pubkey[1:]).hexdigest()
        return f"hx{hash_pub[-40:]}"

    @classmethod
    def address_from_prikey(cls, prikey: bytes):
        pubkey = PrivateKey(prikey).pubkey.serialize(compressed=False)
        return cls.address_from_pubkey(pubkey)

    @classmethod
    def from_address(cls, address: str):
        verifier = SignVerifier()
        verifier.address = address
        return verifier

    @classmethod
    def from_channel(cls, channel: str):
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
        address = cls.address_from_pubkey(pubkey)
        return cls.from_address(address)

    @classmethod
    def from_prikey_file(cls, prikey_file: str, password: Union[str, bytes]):
        if isinstance(password, str):
            password = password.encode()

        if prikey_file.endswith('.der') or prikey_file.endswith('.pem'):
            with open(prikey_file, "rb") as file:
                private_bytes = file.read()
            try:
                if prikey_file.endswith('.der'):
                    temp_private = serialization \
                        .load_der_private_key(private_bytes,
                                              password,
                                              default_backend())
                if prikey_file.endswith('.pem'):
                    temp_private = serialization \
                        .load_pem_private_key(private_bytes,
                                              password,
                                              default_backend())
            except Exception as e:
                raise ValueError(f"Invalid Password: {e}")

            no_pass_private = temp_private.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            key_info = keys.PrivateKeyInfo.load(no_pass_private)
            prikey = utils.long_to_bytes(key_info['private_key'].native['private_key'])
        else:
            from tbears.libs.icx_signer import key_from_key_store
            prikey = key_from_key_store(prikey_file, password)
        return cls.from_prikey(prikey)

    @classmethod
    def from_prikey(cls, prikey: bytes):
        address = cls.address_from_prikey(prikey)
        return cls.from_address(address)


class MakeUpSignatureBase(metaclass=ABCMeta):
    @classmethod
    @abstractmethod
    def make_up_signature(cls):
        pass


class MakeUpSignature(MakeUpSignatureBase):
    @classmethod
    def make_up_signature(cls, serialized_sig, recover_id):
        signature = serialized_sig + bytes([recover_id])
        return Signature(signature)


class MakeUpFlaggedSignature(MakeUpSignatureBase):
    @classmethod
    def make_up_signature(cls, serialized_sig, recover_id):
        signature = bytes([SignatureFlag.RECOVERABLE]) + serialized_sig + bytes([recover_id])
        return FlaggedSignature(signature)


class Signer(SignVerifier):
    def __init__(self):
        super().__init__()
        self.private_key: PrivateKey = None
        self.__make_up_signature = None

    def set_make_up_signature(self, make_up_signature_class: Callable[[bytes, bytes], Signature]):
        self.__make_up_signature = make_up_signature_class

    def sign_data(self, data):
        return self.sign(data, False)

    def sign_hash(self, data):
        return self.sign(data, True)

    def sign(self, data, is_hash: bool):
        if is_hash:
            if isinstance(data, str):
                try:
                    data = data.split("0x")[1] if data.startswith("0x") else data
                    data = binascii.unhexlify(data)
                except Exception as e:
                    logging.error(f"hash data must hex string or bytes \n exception : {e}")
                    return None

        if not isinstance(data, (bytes, bytearray)):
            logging.error(f"data must be bytes \n")
            return None

        if not self.__make_up_signature:
            logging.error(f"There is no make up signature method. ")
            return None

        raw_sig = self.private_key.ecdsa_sign_recoverable(msg=data,
                                                          raw=is_hash,
                                                          digest=hashlib.sha3_256)
        serialized_sig, recover_id = self.private_key.ecdsa_recoverable_serialize(raw_sig)
        return self.__make_up_signature(serialized_sig, recover_id)

    @classmethod
    def from_address(cls, address: str):
        raise TypeError("Cannot create `Signer` from address")

    @classmethod
    def from_channel(cls, channel: str):
        from loopchain import configure as conf

        prikey_file = conf.CHANNEL_OPTION[channel]["private_path"]
        if 'private_password' in conf.CHANNEL_OPTION[channel]:
            password = conf.CHANNEL_OPTION[channel]["private_password"]
        else:
            password = getpass.getpass(f"Input your keystore password for channel({channel}): ")
        return cls.from_prikey_file(prikey_file, password)

    @classmethod
    def from_pubkey(cls, pubkey: bytes):
        raise TypeError("Cannot create `Signer` from pubkey")

    @classmethod
    def from_pubkey_file(cls, pubkey_file: str):
        raise TypeError("Cannot create `Signer` from pubkey file")

    @classmethod
    def from_prikey_file(cls, prikey_file: str, password: Union[str, bytes]):
        return super().from_prikey_file(prikey_file, password)

    @classmethod
    def from_prikey(cls, prikey: bytes):
        auth = Signer()
        auth.set_make_up_signature(MakeUpSignature.make_up_signature)
        auth.private_key = PrivateKey(prikey)
        auth.address = cls.address_from_prikey(prikey)

        # verify
        sign = auth.sign_data(b'TEST')
        if auth.verify_data(b'TEST', sign) is False:
            raise ValueError("Invalid Signature(Peer Certificate load test)")
        return auth


class YubiHsmSigner(SignVerifier):
    def __init__(self):
        super().__init__()
        self.private_key: AsymmetricKey = None

    def sign(self, data, is_hash: bool):
        HsmHelper().open()
        signature = bytes([SignatureFlag.HSM]) + HsmHelper().ecdsa_sign(message=data, is_raw=is_hash)
        return FlaggedHsmSignature(signature)

    @classmethod
    def from_address(cls, address: str):
        raise TypeError("Cannot create `YubiHsmSigner` from address")

    @classmethod
    def from_pubkey(cls, pubkey: bytes):
        verifier = YubiHsmSigner()
        verifier.address = cls.address_from_pubkey(pubkey)
        verifier.private_key = HsmHelper().private_key
        return verifier

    @classmethod
    def from_hsm(cls):
        return cls.from_pubkey(HsmHelper().get_serialize_pub_key())
