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
"""Signature Helper for Tx, Vote, Block Signature verify"""
import hashlib
import logging

import binascii
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils, rsa, padding
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.x509 import Certificate
from secp256k1 import PrivateKey, PublicKey

from loopchain import configure as conf


class PublicVerifier:
    """provide signature verify function using public key"""

    # KEY OPTION JSON NAME
    LOAD_CERT = "load_cert"
    CONSENSUS_CERT_USE = "consensus_cert_use"
    TX_CERT_USE = "tx_cert_use"
    PUBLIC_PATH = "public_path"
    PRIVATE_PATH  = "private_path"
    PRIVATE_PASSWORD = "private_password"
    KEY_LOAD_TYPE = "key_load_type"
    KEY_ID = "key_id"

    def __init__(self, channel):
        """init members to None and set verify function you must run load_key function

        :param channel: using channel name
        """

        self._public_key: EllipticCurvePublicKey = None
        self._cert: Certificate = None
        self._public_der: bytes = None
        self._cert_der: bytes = None

        self._channel = channel
        self._channel_option = conf.CHANNEL_OPTION[self._channel]

        self._tx_verifier_load_function = None
        self._consensus_verifier_load_function = None

        if self._channel_option[self.CONSENSUS_CERT_USE]:
            self._consensus_verifier_load_function = self._load_cert_from_der
        else:
            self._consensus_verifier_load_function = self._load_public_from_der

        if self._channel_option[self.TX_CERT_USE]:
            self._tx_verifier_load_function = self._load_cert_from_der
        else:
            self._tx_verifier_load_function = self._load_public_from_der

    def load_public_for_tx_verify(self, public):
        """load public for tx signature verify

        :param public: der format public key or der format cert
        :return:
        """
        self._tx_verifier_load_function(public)

    def load_public_for_peer_verify(self, public):
        """load public for peer signature verify

        :param public: der format public key or der format cert
        :return:
        """
        self._consensus_verifier_load_function(public)

    @property
    def public_der(self):
        if self._public_der is None:
            self._public_der = self._public_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        return self._public_der

    @property
    def cert_der(self):
        if self._cert_der is None:
            self._cert_der = self._cert.public_bytes(
                encoding=serialization.Encoding.DER
            )
        return self._cert_der

    @property
    def tx_cert(self):
        if self._channel_option[self.TX_CERT_USE]:
            return self.cert_der
        return self.public_der

    @property
    def peer_cert(self):
        if self._channel_option[self.TX_CERT_USE]:
            return self.cert_der
        return self.public_der

    def _load_public_from_der(self, public_der: bytes):
        """load public key using der format public key

        :param public_der: der format public key
        :raise ValueError: public_der format is wrong
        """
        self._public_key = serialization.load_der_public_key(
            public_der,
            backend=default_backend()
        )

    def _load_public_from_object(self, public: EllipticCurvePublicKey):
        """load public key using public object

        :param public: der format public key
        :raise ValueError: public type is not EllipticCurvePublicKey
        """
        if isinstance(public, EllipticCurvePublicKey):
            self._public_key = public
        else:
            raise ValueError("public must EllipticCurvePublicKey Object")

    def _load_public_from_pem(self, public_pem: bytes):
        """load public key using pem format public key

        :param public_pem: der format public key
        :raise ValueError: public_der format is wrong
        """
        self._public_key = serialization.load_pem_public_key(
            public_pem,
            backend=default_backend()
        )

    def _load_cert_from_der(self, cert_der):
        cert: Certificate = x509.load_der_x509_certificate(cert_der, default_backend())
        self._cert = cert
        self._public_key = cert.public_key()

    def _load_cert_from_pem(self, cert_pem):
        cert: Certificate = x509.load_pem_x509_certificate(cert_pem, default_backend())
        self._cert = cert
        self._public_key = cert.public_key()

    def verify_data(self, data, signature) -> bool:
        """개인키로 서명한 데이터 검증

        :param data: 서명 대상 원문
        :param signature: 서명 데이터
        :return: 서명 검증 결과(True/False)
        """
        pub_key = self._public_key
        return self.verify_data_with_publickey(public_key=pub_key, data=data, signature=signature)

    def verify_hash(self, digest, signature) -> bool:
        """개인키로 서명한 해시 검증

        :param digest: 서명 대상 해시
        :param signature: 서명 데이터
        :return: 서명 검증 결과(True/False)
        """
        # if hex string
        if isinstance(digest, str):
            try:
                digest = binascii.unhexlify(digest)
            except Exception as e:
                logging.warning(f"verify hash must hex or bytes {e}")
                return False

        return self.verify_data_with_publickey(public_key=self._public_key,
                                               data=digest,
                                               signature=signature,
                                               is_hash=True)

    @staticmethod
    def verify_data_with_publickey(public_key, data: bytes, signature: bytes, is_hash: bool=False) -> bool:
        """서명한 DATA 검증

        :param public_key: 검증용 공개키
        :param data: 서명 대상 원문
        :param signature: 서명 데이터
        :param is_hash: 사전 hashed 여부(True/False
        :return: 서명 검증 결과(True/False)
        """
        hash_algorithm = hashes.SHA256()
        if is_hash:
            hash_algorithm = utils.Prehashed(hash_algorithm)

        if isinstance(public_key, ec.EllipticCurvePublicKeyWithSerialization):
            try:
                public_key.verify(
                    signature=signature,
                    data=data,
                    signature_algorithm=ec.ECDSA(hash_algorithm)
                )
                return True
            except InvalidSignature:
                logging.debug("InvalidSignatureException_ECDSA")
        else:
            logging.debug("Invalid PublicKey Type : %s", type(public_key))

        return False

    @staticmethod
    def verify_data_with_publickey_rsa(public_key, data: bytes, signature: bytes, is_hash: bool=False) -> bool:
        """서명한 DATA 검증

        :param public_key: 검증용 공개키
        :param data: 서명 대상 원문
        :param signature: 서명 데이터
        :param is_hash: 사전 hashed 여부(True/False
        :return: 서명 검증 결과(True/False)
        """
        hash_algorithm = hashes.SHA256()
        if is_hash:
            hash_algorithm = utils.Prehashed(hash_algorithm)

        if isinstance(public_key, rsa.RSAPublicKeyWithSerialization):
            try:
                public_key.verify(
                    signature,
                    data,
                    padding.PKCS1v15(),
                    hash_algorithm
                )
                return True
            except InvalidSignature:
                logging.debug("InvalidSignatureException_RSA")
        else:
            logging.debug("Unknown PublicKey Type : %s", type(public_key))

        return False


class IcxVerifier:
    _pri = PrivateKey()

    def __init__(self):
        self._address: str = None
        self._serialize_pubkey: bytes = None

    @property
    def address(self):
        return self._address

    @property
    def peer_cert(self):
        return self._serialize_pubkey

    def _init_using_pub(self, pubkey: bytes):
        self._serialize_pubkey = pubkey
        hash_pub = hashlib.sha3_256(self._serialize_pubkey[1:]).hexdigest()
        self._address = f"hx{hash_pub[-40:]}"

    def init_and_verify_address(self, pubkey: bytes, address: str):
        self._init_using_pub(pubkey)
        if self._address != address:
            raise ValueError(f"Invalid Address : {address}")

    def verify_data(self, origin_data: bytes, signature: bytes):
        return self.__verify_signature(origin_data, signature, False)

    def verify_hash(self, origin_data, signature):
        return self.__verify_signature(origin_data, signature, True)

    def __verify_signature(self, origin_data: bytes, signature: bytes, is_hash):
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
            return self._serialize_pubkey == extract_pub
        except Exception:
            logging.debug(f"signature verify fail : {origin_data} {signature}")
            return False


class PublicVerifierContainer:
    """PublicVerifier Container for often usaged"""

    __public_verifier = {}

    @classmethod
    def get_public_verifier(cls, channel, serialized_public: bytes) -> PublicVerifier:
        try:
            channel_public_verifier_list = cls.__public_verifier[channel]
        except KeyError as e:
            cls.__public_verifier[channel] = {}
            return cls.__create_public_verifier(channel, serialized_public)
        else:
            try:
                return channel_public_verifier_list[serialized_public]
            except KeyError as e:
                return cls.__create_public_verifier(channel, serialized_public)

    @classmethod
    def __create_public_verifier(cls, channel, serialized_public: bytes) -> PublicVerifier:
        """create Public Verifier use serialized_public deserialize public key

        :param serialized_public: der public key
        :return: PublicVerifier
        """

        public_verifier = PublicVerifier(channel)
        public_verifier.load_public_for_tx_verify(serialized_public)
        cls.__public_verifier[channel][serialized_public] = public_verifier

        return public_verifier
