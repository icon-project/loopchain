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
""" A class for certification authorization """

import datetime
import logging

from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.exceptions import InvalidSignature
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import PublicFormat
from os.path import join


class CertificateAuthorization:
    """
    Peer들의 인증을 처리한다.
    """

    # 인증서 파일명
    CERT_NAME = "cert.pem"
    # 개인키 파일명
    PRI_NAME = "key.pem"

    # CA 인증서
    __ca_cert = None
    # CA PRIVATE KEY
    __ca_pri = None

    def __init__(self):
        pass

    # def load_pki(self, ca_cert_path, private_key_path):
    def load_pki(self, cert_path: str, cert_pass=None):
        """
        인증서 로드

        :param cert_path: 인증서 경로
        :param cert_pass: 개인키 패스워드
        """
        ca_cert_file = join(cert_path, self.CERT_NAME)
        ca_pri_file = join(cert_path, self.PRI_NAME)

        # 인증서/개인키 로드
        with open(ca_cert_file, "rb") as der:
            cert_bytes = der.read()
            self.__ca_cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
        with open(ca_pri_file, "rb") as der:
            private_bytes = der.read()
            try:
                self.__ca_pri = serialization.load_pem_private_key(private_bytes, cert_pass, default_backend())
            except ValueError:
                logging.debug("Invalid Password")

        # 인증서 키 쌍 검증
        sign = self.sign_data(b'TEST')
        if self.verify_data(b'TEST', sign) is False:
            logging.debug("Invalid Signature(Root Certificate load test)")

    def get_sign_public_key(self):
        if self.__ca_cert is None:
            return None
        else:
            return self.__ca_cert.public_key

    def sign_data(self, data: bytes) -> bytes:
        """
        CA 개인키로 DATA 서명
        :param data: 서명 대상 원문
        :return: 서명
        """
        if isinstance(self.__ca_pri, ec.EllipticCurvePrivateKeyWithSerialization):
            signer = self.__ca_pri.signer(ec.ECDSA(hashes.SHA256()))
            signer.update(data)
            return signer.finalize()
        elif isinstance(self.__ca_pri, rsa.RSAPrivateKeyWithSerialization):
            return self.__ca_pri.sign(
                data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        else:
            logging.debug("Unknown PrivateKey Type : %s", type(self.__ca_pri))
            return None

    def verify_data(self, data: bytes, signature: bytes) -> bool:
        """
        CA 개인키로 서명한 DATA 검증
        :param data: 서명 대상 원문
        :param signature: 서명 데이터
        :return: 검증 결과(True/False)
        """
        pub_key = self.__ca_cert.public_key()
        return self.verify_data_with_publickey(public_key=pub_key, data=data, signature=signature)

    def verify_data_with_publickey(self, public_key, data: bytes, signature: bytes) -> bool:
        """
        서명한 DATA검증
        :param public_key: 검증용 공개키
        :param data: 서명 대상 원문
        :param signature: 서명 데이터
        :return: 검증 결과(True/False)
        """
        if isinstance(public_key, ec.EllipticCurvePublicKeyWithSerialization):
            try:
                public_key.verify(
                    signature=signature,
                    data=data,
                    signature_algorithm=ec.ECDSA(hashes.SHA256())
                )
                return True
            except InvalidSignature:
                logging.debug("InvalidSignatureException_ECDSA")
        elif isinstance(public_key, rsa.RSAPublicKeyWithSerialization):
            try:
                public_key.verify(
                    signature,
                    data,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                return True
            except InvalidSignature:
                logging.debug("InvalidSignatureException_RSA")
        else:
            logging.debug("Unknown PublicKey Type : %s", type(public_key))

        return False

    def verify_data_with_dercert(self, cert_der, data: bytes, signature: bytes) -> bool:
        """
        서명 및 인증서 검증
        :param cert_der: 인증서(der bytes)
        :param data: 서명 원문
        :param signature: 서명
        :return: 검증 결과(True/False)
        """
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        return self.verify_data_with_cert(cert=cert, data=data, signature=signature)

    def verify_data_with_cert(self, cert, data: bytes, signature: bytes) -> bool:
        """
        서명 및 인증서 검증
        :param cert: 인증서
        :param data: 서명 원문
        :param signature: 서명
        :return: 검증 결과(True/False)
        """
        # LOOPCHAIN-61 인증서 검증
        if self.verify_certificate(cert):
            # 인증서로 사인한 내용 검증
            cert_pub = cert.public_key()
            validation_result = self.verify_data_with_publickey(public_key=cert_pub, data=data, signature=signature)
            if validation_result is False:
                logging.debug(f"signature validation is fail")
            return validation_result
        else:
            logging.debug(f"certificate validation is fail")
            return False

    def verify_certificate_der(self, der_cert):
        """
        인증서 검증
        :param der_cert: DER 형식의 하위인증서
        :return: 검증 결과
        """
        cert = x509.load_der_x509_certificate(der_cert, default_backend())
        return self.verify_certificate(cert)

    def verify_certificate(self, peer_cert):
        """
        인증서 검증
        :param peer_cert: 하위인증서
        :return: 검증 결과
        """
        # 인증서 유효기간 검증
        not_after = peer_cert.not_valid_after
        now = datetime.datetime.now()
        if not_after < now:
            logging.error("Certificate is Expired")
            return False

        # 인증서 서명 검증
        # CA 인증서의 경우 검증하지 않음
        if self.__ca_cert.signature == peer_cert.signature:
            return True
        ca_pub = self.__ca_cert.public_key()
        signature = peer_cert.signature
        data = peer_cert.tbs_certificate_bytes

        validation_result = False
        if isinstance(ca_pub, ec.EllipticCurvePublicKeyWithSerialization):
            try:
                ca_pub.verify(
                    signature=signature,
                    data=data,
                    signature_algorithm=ec.ECDSA(hashes.SHA256())
                )
                validation_result = True
            except InvalidSignature:
                logging.debug("InvalidSignatureException_ECDSA")
        elif isinstance(ca_pub, rsa.RSAPublicKeyWithSerialization):
            try:
                ca_pub.verify(
                    signature,
                    data,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                validation_result = True
            except InvalidSignature:
                logging.debug("InvalidSignatureException_RSA")
        else:
            logging.debug("Unknown PublicKey Type : %s", type(ca_pub))

        return validation_result

    def generate_peer_token(self, peer_sign, peer_cert, peer_id, peer_target,
                            group_id, peer_type, rand_key, token_interval):
        peer_info = b''.join([peer_id.encode('utf-8'),
                              peer_target.encode('utf-8'),
                              group_id.encode('utf-8')]) + bytes([peer_type])
        data = peer_info + rand_key

        cert = x509.load_der_x509_certificate(peer_cert, default_backend())
        if self.verify_data_with_cert(cert=cert, data=data, signature=peer_sign):

            time = datetime.datetime.now() + datetime.timedelta(minutes=token_interval)
            date = int(time.timestamp() * 1000).to_bytes(length=8, byteorder='big')

            peer_pub = cert.public_key().public_bytes(encoding=serialization.Encoding.DER,
                                                      format=PublicFormat.SubjectPublicKeyInfo)

            # token_bytes = peer_id || peer_target || group_id || peer_type || peer_pub
            token_bytes = peer_info + date + peer_pub
            logging.debug("TBS Token[%s]", token_bytes.hex())

            # token = date || CA_Sign(token_bytes)
            signed_token = self.sign_data(token_bytes)
            token = b''.join([date, signed_token]).hex()
            return token
        else:
            logging.debug("The validation for signature or certificate is fail.")
            return None

    def verify_peer_token(self, peer_token, peer, peer_type):
        token_time = peer_token[:16]
        token_sign = peer_token[16:]
        current_date = int(datetime.datetime.now().timestamp() * 1000)
        token_date = int(token_time, 16)
        if current_date > token_date:
            return False

        date = bytes.fromhex(token_time)

        peer_info = b''.join([peer.peer_id.encode('utf-8'),
                              peer.target.encode('utf-8'),
                              peer.group_id.encode('utf-8')]) + bytes([peer_type])

        peer_cert = x509.load_der_x509_certificate(bytes.fromhex(peer.cert), default_backend())
        peer_pub = peer_cert.public_key().public_bytes(encoding=serialization.Encoding.DER,
                                                       format=PublicFormat.SubjectPublicKeyInfo)

        token_bytes = peer_info + date + peer_pub
        logging.debug("TBS Token(V) : %s", token_bytes.hex())
        signature = bytes.fromhex(token_sign)

        return self.verify_data_with_cert(cert=self.__ca_cert, data=token_bytes, signature=signature)

    @property
    def is_secure(self):
        return self.__ca_cert is not None and self.__ca_pri is not None
