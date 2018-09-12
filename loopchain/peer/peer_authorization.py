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
""" A class for authorization of Peer """

import binascii
import datetime
import logging

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec, utils
from cryptography.x509 import Certificate

import loopchain.utils as util
from loopchain import configure as conf
from loopchain.configure_default import KeyLoadType
from loopchain.tools.signature_helper import PublicVerifier


class PeerAuthorization(PublicVerifier):
    """Peer의 인증을 처리한다"""
    __ca_cert = None
    __token = None

    # RequestPeer 요청 생성 시 저장 정보
    __peer_info = None

    def __init__(self, channel, rand_table=None):
        """create key_pair for signature using conf.CHANNEL_OPTION

        :param channel: channel name
        :param rand_table: for RandomTable Derivation key set, create using table
        :param agent_pin: for KMS, kms connection agent pin
        """

        super().__init__(channel)
        self.__peer_pri = None

        # option check
        if not self._channel_option[self.LOAD_CERT]:
            if self._channel_option[self.CONSENSUS_CERT_USE] or self._channel_option[self.TX_CERT_USE]:
                logging.error("public key load type can't use cert")
                util.exit_and_msg("public key load type can't use cert")

        try:
            if self._channel_option[self.KEY_LOAD_TYPE] == conf.KeyLoadType.FILE_LOAD:
                logging.info("key load type : file load")
                logging.info(f"public file : {conf.CHANNEL_OPTION[self._channel][self.PUBLIC_PATH]}")
                logging.info(f"private file : {conf.CHANNEL_OPTION[self._channel][self.PRIVATE_PATH]}")

                # load public key
                with open(conf.CHANNEL_OPTION[self._channel][self.PUBLIC_PATH], "rb") as public:
                    public_bytes = public.read()
                    if conf.CHANNEL_OPTION[self._channel][self.LOAD_CERT]:
                        self.__load_cert(public_bytes)
                    else:
                        self.__load_public(public_bytes)

                # load private key
                self.__load_private(pri_path=conf.CHANNEL_OPTION[self._channel][self.PRIVATE_PATH],
                                    pri_pass=conf.CHANNEL_OPTION[self._channel][self.PRIVATE_PASSWORD])

            elif self._channel_option[self.KEY_LOAD_TYPE] == conf.KeyLoadType.KMS_LOAD:
                from loopchain.tools.kms_helper import KmsHelper
                cert, private = KmsHelper().get_signature_cert_pair(conf.CHANNEL_OPTION[self._channel][self.KEY_ID])
                # KMS not support public key load
                if conf.CHANNEL_OPTION[self._channel][self.LOAD_CERT]:
                    self.__load_cert(cert)
                else:
                    raise Exception("KMS Load does't support public key load")

                self.__load_private_byte(private)

            elif self._channel_option[self.KEY_LOAD_TYPE] == KeyLoadType.RANDOM_TABLE_DERIVATION:
                logging.info("key load type : random table derivation")
                # Random Table derivation not support cert key load
                if conf.CHANNEL_OPTION[self._channel][self.LOAD_CERT]:
                    raise Exception("KMS Load does't support public key load")

                self.__peer_pri = self.__key_derivation(rand_table)
                self._load_public_from_object(self.__peer_pri.public_key())

            else:
                raise Exception(f"conf.KEY_LOAD_TYPE : {conf.CHANNEL_OPTION[channel][self.KEY_LOAD_TYPE]}"
                                f"\nkey load option is wrong")

        except Exception as e:
            logging.error(e)
            util.exit_and_msg(f"key load fail cause : {e}")

    def __load_public(self, public_bytes):
        """load certificate

        :param public_bytes: der or pem format certificate
        """
        try:
            self._load_public_from_der(public_bytes)
        except Exception as e:
            self._load_public_from_pem(public_bytes)

    def __load_cert(self, cert_bytes: bytes):
        """load certificate

        :param cert_bytes: der or pem format certificate
        """
        try:
            cert: Certificate = self._load_cert_from_der(cert_bytes)
        except Exception as e:
            cert: Certificate = self._load_cert_from_pem(cert_bytes)

    def __load_private(self, pri_path, pri_pass=None):
        """인증서 로드

        :param pri_path: 개인키 경로
        :param pri_pass: 개인키 패스워드
        :return:
        """
        if isinstance(pri_pass, str):
            pri_pass = pri_pass.encode()
        # 인증서/개인키 로드
        with open(pri_path, "rb") as der:
            private_bytes = der.read()
        self.__load_private_byte(private_bytes, pri_pass)

    def __load_private_byte(self, private_bytes, private_pass=None):
        """private load from bytes string

        :param private_bytes: private byte
        :param private_pass: private password
        :return:
        """

        try:
            try:
                self.__peer_pri = serialization.load_der_private_key(private_bytes, private_pass, default_backend())
            except Exception as e:
                # try pem type private load
                self.__peer_pri = serialization.load_pem_private_key(private_bytes, private_pass, default_backend())

        except ValueError as e:
            logging.exception(f"error {e}")
            util.exit_and_msg("Invalid Password")

        # 키 쌍 검증
        sign = self.sign_data(b'TEST')
        if self.verify_data(b'TEST', sign) is False:
            util.exit_and_msg("Invalid Signature(Peer Certificate load test)")

    def set_peer_info(self, peer_id, peer_target, group_id, peer_type):
        self.__peer_info = b''.join([peer_id.encode('utf-8'),
                                     peer_target.encode('utf-8'),
                                     group_id.encode('utf-8')]) + bytes([peer_type])

    def sign_data(self, data, is_hash=False):
        """인증서 개인키로 DATA 서명

        :param data: 서명 대상 원문
        :param is_hash: when data is hashed True
        :return: 서명 데이터
        """
        hash_algorithm = hashes.SHA256()
        if is_hash:
            hash_algorithm = utils.Prehashed(hash_algorithm)
            if isinstance(data, str):
                try:
                    data = binascii.unhexlify(data)
                except Exception as e:
                    logging.error(f"hash data must hex string or bytes \n exception : {e}")
                    return None

        if not isinstance(data, (bytes, bytearray)):
            logging.error(f"data must be bytes \n")
            return None

        if isinstance(self.__peer_pri, ec.EllipticCurvePrivateKeyWithSerialization):
            return self.__peer_pri.sign(
                data,
                ec.ECDSA(hash_algorithm))
        elif isinstance(self.__peer_pri, rsa.RSAPrivateKeyWithSerialization):
            return self.__peer_pri.sign(
                data,
                padding.PKCS1v15(),
                hash_algorithm
            )
        else:
            logging.error("Unknown PrivateKey Type : %s", type(self.__peer_pri))
            return None

    def generate_request_sign(self, rand_key):
        """RequestPeer 서명을 생성한다.

        set_peer_info 함수가 우선 실행되어야 한다.
        sign_peer(peer_id || peer_target || group_id || peet_type || rand_key)
        :param rand_key: 서버로 부터 수신한 랜덤
        :return: 서명
        """
        tbs_data = self.__peer_info + bytes.fromhex(rand_key)
        return self.sign_data(tbs_data)

    def get_token_time(self, token):
        """Token의 유효시간을 검증하고 토큰을 검증하기 위한 데이터를 반환한다.

        :param token: 검증 대상 Token
        :return: 검증 실패 시 None, 성공 시 토큰 검증을 위한 데이터
        """
        token_time = token[2:18]
        token_date = int(token_time, 16)
        current_date = int(datetime.datetime.now().timestamp() * 1000)
        if current_date < token_date:
            return bytes.fromhex(token_time)

        return None

    @staticmethod
    def __key_derivation(rand_table):
        """key derivation using rand_table and conf.FIRST_SEED conf.SECOND_SEED

        :param rand_table:
        :return: private_key
        """
        hash_value = rand_table[conf.FIRST_SEED] + rand_table[conf.SECOND_SEED] + conf.MY_SEED
        return ec.derive_private_key(hash_value, ec.SECP256K1(), default_backend())
