import hashlib
import struct

from asn1crypto import keys
from cryptography.hazmat.primitives import serialization
from yubihsm import YubiHsm
from yubihsm.core import AuthSession
from yubihsm.objects import AsymmetricKey
from yubihsm.defs import OBJECT, COMMAND

from loopchain import configure as conf
from loopchain.components import SingletonMetaClass


class HsmHelper(metaclass=SingletonMetaClass):
    """Help Get CertPair and Keys From KMS"""
    def __init__(self):
        """init HSM and Session

        """
        self.__hsm: YubiHsm = None
        self.__session: AuthSession = None
        self.__private_key: AsymmetricKey = None
        self.__public_key: bytes = None

    @property
    def private_key(self):
        return self.__private_key

    @property
    def public_key(self):
        return self.__public_key

    def open(self):
        if not self.__hsm:
            self.__hsm = YubiHsm.connect(conf.HSM_YUBI_CONNECTOR)
        self.__session = self.__hsm.create_session_derived(conf.HSM_YUBI_SESSION_ID, conf.HSM_YUBI_SESSION_PASSWORD)

        if not (self.__private_key and self.__public_key):
            self.__load_key_pair()

    def close(self):

        """
        Close session and HSM device.
        :return:
        """
        self.__session.close()
        self.__hsm.close()

    def __load_key_pair(self):
        self.__private_key = self.__session.get_object(conf.HSM_YUBI_KEY_ID, OBJECT.ASYMMETRIC_KEY)
        self.__public_key = self.__private_key.get_public_key()

        # utils.logger.notice(f"loaded key pair : {self.__private_key.get_info()}/{self.__public_key}")

    def get_serialize_pub_key(self):
        key_info = keys.PublicKeyInfo.load(
            self.__public_key.public_bytes(encoding=serialization.Encoding.DER,
                                           format=serialization.PublicFormat.SubjectPublicKeyInfo)
        )
        return key_info['public_key'].native

    def ecdsa_sign(self, message: bytes, is_raw: bool = True, digest=hashlib.sha3_256()):
        """Sign data using ECDSA.

        :param bytes message: The data to sign.
        :param digest: (optional) The algorithm to use when hashing the data.
        :param is_raw: (optional) The message is raw data if true.
        :return: The signature.
        :rtype: bytes
        """
        if not is_raw:
            digest.update(message)
            data = digest.digest()
        else:
            data = message

        length = len(data)
        msg = struct.pack('!H%ds' % length, self.__private_key.id, data.rjust(length, b'\0'))
        signature = self.__session.send_secure_cmd(COMMAND.SIGN_ECDSA, msg)
        self.__session.close()
        return signature
