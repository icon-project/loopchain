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
""" A class for signature signer of Peer"""

import binascii
import getpass
import hashlib
import logging
from abc import ABCMeta, abstractmethod
from typing import Union

from asn1crypto import keys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from secp256k1 import PrivateKey

from loopchain import utils
from loopchain.blockchain import SignatureFlag, FlaggedHsmSignature, Signature, FlaggedSignature, IntEnum
from loopchain.tools.hsm_helper import HsmHelper


class SignatureType(IntEnum):
    NONE = 0
    FLAGGED = 1


class SignerBase(metaclass=ABCMeta):
    _private_key = None
    private_key = None
    address: 'ExternalAddress' = None

    def sign_data(self, data, signature_type: SignatureType):
        return self.sign(data, False, signature_type)

    def sign_hash(self, data, signature_type: SignatureType):
        return self.sign(data, True, signature_type)

    @classmethod
    def address_from_prikey(cls, prikey: bytes):
        pubkey = PrivateKey(prikey).pubkey.serialize(compressed=False)
        return utils.address_from_pubkey(pubkey)

    @abstractmethod
    def sign(self):
        raise NotImplementedError


class MakeUpRecoverableSignBase(metaclass=ABCMeta):
    @classmethod
    @abstractmethod
    def make_up_signature(cls, serialized_sig, recover_id):
        pass


class MakeUpRecoverableSign(MakeUpRecoverableSignBase):
    @classmethod
    def make_up_signature(cls, serialized_sig, recover_id) -> Signature:
        signature = serialized_sig + bytes([recover_id])
        return Signature(signature)


class MakeUpFlaggedRecoverableSign(MakeUpRecoverableSignBase):
    @classmethod
    def make_up_signature(cls, serialized_sig, recover_id) -> FlaggedSignature:
        signature = bytes([SignatureFlag.RECOVERABLE]) + serialized_sig + bytes([recover_id])
        return FlaggedSignature(signature)


class RecoverableSigner(SignerBase):
    __signature_formatter = {
        SignatureType.NONE: MakeUpRecoverableSign,
        SignatureType.FLAGGED: MakeUpFlaggedRecoverableSign
    }

    @classmethod
    def from_channel_with_private_key(cls, channel: str):
        from loopchain import configure as conf

        prikey_file = conf.CHANNEL_OPTION[channel]["private_path"]
        if 'private_password' in conf.CHANNEL_OPTION[channel]:
            password = conf.CHANNEL_OPTION[channel]["private_password"]
        else:
            password = getpass.getpass(f"Input your keystore password for channel({channel}): ")
        return cls.from_prikey_file(prikey_file, password)

    @classmethod
    def from_prikey_file(cls, prikey_file: str, password: Union[str, bytes]):
        if isinstance(password, str):
            password = password.encode()

        if prikey_file.endswith('.der') or prikey_file.endswith('.pem'):
            with open(prikey_file, "rb") as file:
                private_bytes = file.read()
            try:
                if prikey_file.endswith('.der'):
                    temp_private = serialization.load_der_private_key(private_bytes, password, default_backend())
                if prikey_file.endswith('.pem'):
                    temp_private = serialization.load_pem_private_key(private_bytes, password, default_backend())
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
        from loopchain.crypto.signature import RecoverableSignatureVerifier

        signer = RecoverableSigner()
        signer.private_key = PrivateKey(prikey)
        signer.address = cls.address_from_prikey(prikey)

        signature = signer.sign_data(b'TEST', SignatureType.NONE)
        verifier = RecoverableSignatureVerifier.from_address(signer.address)
        if verifier.verify_data(b'TEST', signature) is False:
            raise ValueError("Invalid Signature.")
        return signer

    def sign(self, data, is_hash: bool, signature_type: SignatureType):
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

        raw_sig = self.private_key.ecdsa_sign_recoverable(msg=data,
                                                          raw=is_hash,
                                                          digest=hashlib.sha3_256)
        serialized_sig, recover_id = self.private_key.ecdsa_recoverable_serialize(raw_sig)
        return self.__signature_formatter[signature_type].make_up_signature(serialized_sig, recover_id)


class HSMSigner(SignerBase):

    @classmethod
    def from_hsm(cls):
        signer = HSMSigner()
        signer.address = utils.address_from_pubkey(HsmHelper().get_serialize_pub_key())
        signer.private_key = HsmHelper().private_key
        return signer

    def sign(self, data, is_hash: bool, signature_type: SignatureType):
        HsmHelper().open()
        signature = bytes([SignatureFlag.HSM]) + HsmHelper().ecdsa_sign(message=data, is_raw=is_hash)
        return FlaggedHsmSignature(signature)
