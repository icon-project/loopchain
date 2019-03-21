import hashlib
import logging
import struct

from asn1crypto import keys
from cryptography.hazmat.backends.openssl.ec import _EllipticCurvePublicKey

from cryptography.hazmat.primitives import serialization
from secp256k1 import PrivateKey, PublicKey, ffi
from yubihsm import YubiHsm
from yubihsm.core import AuthSession
from yubihsm.objects import AsymmetricKey
from yubihsm.defs import OBJECT, COMMAND
from loopchain import configure as conf
from loopchain import utils
from loopchain.components import SingletonMetaClass


class HsmHelper(metaclass=SingletonMetaClass):
    """Help Get CertPair and Keys From KMS"""
    def __init__(self):
        """init HSM and Session

        """
        self.__hsm: YubiHsm = None
        self.__session: AuthSession = None
        # TODO: private key가 메모리 상에 계속 존재해도 될까 ? Yubi쪽 Object지만 .. 매번 key를 load해야 할까 ?
        self.__private_key: AsymmetricKey = None
        self.__public_key: bytes = None

    @property
    def private_key(self):
        return self.__private_key

    @property
    def public_key(self):
        return self.__public_key

    def open(self):
        if self.__session:
            self.close()

        self.__hsm = YubiHsm.connect(conf.HSM_YUBI_CONNECTOR)
        self.__session = self.__hsm.create_session_derived(conf.HSM_YUBI_SESSION_ID, conf.HSM_YUBI_SESSION_PASSWORD)

        if not (self.__private_key and self.__public_key):
            self.__load_key_pair()

    def close(self):

        """
        Clean up Session and HSM
        :return:
        """
        self.__session.close()
        self.__hsm.close()

    def __load_key_pair(self):
        self.__private_key = self.__session.get_object(conf.HSM_YUBI_KEY_ID, OBJECT.ASYMMETRIC_KEY)
        # self.__public_key = self.__serialize_pub_key(self.__private_key.get_public_key())
        self.__public_key = self.__private_key.get_public_key()

        utils.logger.notice(f"loaded key pair : {self.__private_key.get_info()}/{self.__public_key}")

    def __serialize_pub_key(self, public_key: _EllipticCurvePublicKey) -> bytes:
        key_info = keys.PublicKeyInfo.load(
            public_key.public_bytes(encoding=serialization.Encoding.DER,
                                    format=serialization.PublicFormat.SubjectPublicKeyInfo)
        )
        return key_info['public_key'].native

    def get_serialize_pub_key(self):
        return self.__serialize_pub_key(self.__public_key)

    def ecdsa_sign(self, message: bytes, is_raw: bool = True, digest=hashlib.sha3_256()):
        """Sign data using ECDSA.

        :param bytes message: The data to sign.
        :param digest: (optional) The algorithm to use when hashing the data.
        :param is_raw: (optional) The message is raw data if true.
        :return: The resulting signature.
        :rtype: bytes
        """
        if not is_raw:
            digest.update(message)
            data = digest.digest()
        else:
            data = message

        length = len(data)
        msg = struct.pack('!H%ds' % length, self.__private_key.id, data.rjust(length, b'\0'))
        return self.__session.send_secure_cmd(COMMAND.SIGN_ECDSA, msg)

    def ecdsa_recover(self, origin_data: bytes, norma_signature: bytes, is_raw: bool, digest=hashlib.sha3_256) -> bytes:
        secp256k1_key = PrivateKey()
        deserialized_sig = secp256k1_key.ecdsa_deserialize(norma_signature)
        utils.logger.notice(f"deserialized_sig: {bytes(deserialized_sig.data)}")

        for i in range(4):
            recover_sig = ffi.new('secp256k1_ecdsa_recoverable_signature *')
            for j in range(len(bytes(deserialized_sig.data))):
                recover_sig.data[j] = deserialized_sig.data[j]

            recover_sig.data[64] = i
            recoverable_serialized_sig = secp256k1_key.ecdsa_recoverable_serialize(recover_sig)
            utils.logger.notice(f"recoverable_serialized_sig: {recoverable_serialized_sig}")

            recoverable_sig = secp256k1_key.ecdsa_recoverable_deserialize(recoverable_serialized_sig[0], i)
            utils.logger.notice(f"recoverable_sig: {bytes(recoverable_sig.data)}")

            try:
                raw_public_key = secp256k1_key.ecdsa_recover(origin_data, recoverable_sig, is_raw, digest)
                pub_key = PublicKey(raw_public_key).serialize(compressed=False)

                utils.logger.notice(f"pub_key: \n{pub_key}")
                # utils.logger.notice(f"origin_pub_key: \n{native_pub}")
                # utils.logger.notice(f"------------------------{pub_key == native_pub}")
                # if pub_key == native_pub:
                #     break

            except Exception as e:
                logging.debug(f"Exception: {e}")

        return None


class CreateSecretKeyException(Exception):
    """When Raise KMS create SecretKey for private key encryption Fail """
    pass


class PrivateKeyNotFoundException(Exception):
    """When Raise KMS Cannot found PrivateKey"""
    pass


class GetPrivateKeyException(Exception):
    """When Raise KMS Get PrivateKey Fail"""
    pass


class CertNotFoundException(Exception):
    """When Raise KMS Cannot found Certificate"""
    pass


class GetCertKeyException(Exception):
    """When Raise KMS Get Certificate Fail"""
    pass
