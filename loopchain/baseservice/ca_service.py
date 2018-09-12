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
""" A module for issue certificate of CA and Peer """

import datetime
import logging
import json

from enum import IntEnum
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
from os import mkdir, listdir, remove
from os.path import exists, join, isfile, isdir


class CertificatePurpose(IntEnum):
    signature = 0
    encryption = 1
    ca = 2


class CAService:
    """CA 인증서, Peer 인증서를 발급한다.
    """
    # 인증서/개인키 파일명
    CERT_FILE = "cert.pem"
    PRI_FILE = "key.pem"

    # Peer 보관 CA 인증서 파일명
    PEER_CA_CERT_FILE = "ca.pem"

    # CA 인증서 PATH
    __CA = "CA"
    __CA_PATH = None
    __DEFAULT_PATH = None

    # 인증서/개인키
    __ca_cert = None
    __ca_pri = None

    # 최종 일련번호
    __LAST_CA_INDEX = 0
    __LAST_PEER_INDEX = 1

    # Peer 인증서 목록
    __PEER_CERT = {}

    # 유효기간
    __ca_expired = 20
    __peer_expired = 10

    # subject_alt_name DOMAIN
    __DOMAIN = "theloop.co.kr"

    def __init__(self, default_dir=None, password=None):
        logging.debug("Default PATH : %s", default_dir)
        if default_dir is not None:
            self.__DEFAULT_PATH = default_dir
            self.__CA_PATH = join(default_dir, self.__CA)
            self.__load_ca(password)
            self.__load_peer()

    def __load_ca(self, password=None):
        """CA 인증서/개인키를 읽어들임

        :param password: 개인키 복호화 비밀번호
        """
        cert_dir = self.__CA_PATH
        logging.debug("Read CA Path : %s", cert_dir)

        if exists(cert_dir) is False:
            logging.debug("CA Certificate is None")
            return None

        _ca_cert_file = join(cert_dir, self.CERT_FILE)
        _ca_pri_file = join(cert_dir, self.PRI_FILE)
        if exists(_ca_cert_file):
            f = open(_ca_cert_file, "rb")
            cert_bytes = f.read()
            f.close()
            self.__ca_cert = self.convert_x509cert_from_pem(cert_bytes)
            self.__LAST_CA_INDEX = self.__ca_cert.serial_number
        else:
            logging.debug("Certificate File loading fail : %s", _ca_cert_file)

        if exists(_ca_pri_file):
            f = open(_ca_pri_file, "rb")
            pri_bytes = f.read()
            f.close()
            self.__ca_pri = self.convert_privatekey_from_pem(pri_pem=pri_bytes, password=password)
        else:
            logging.debug("PrivateKey File loading fail : %s", _ca_pri_file)

        if self.sign_test() is False:
            self.__ca_cert = None
            self.__ca_pri = None
            logging.debug("CA Certificate/PrivateKey loading... Fail")
        else:
            logging.debug("CA Certificate/PrivateKey loading... Success")

    def __load_peer(self):
        """Peer 인증서를 읽어들임
        """
        path = self.__DEFAULT_PATH
        dir_list = [f for f in listdir(path) if isdir(join(path, f))]
        for dir_name in dir_list:
            if dir_name != self.__CA:
                cert_name = join(path, dir_name, self.CERT_FILE)
                if exists(cert_name):
                    f = open(cert_name, "rb")
                    cert_bytes = f.read()
                    f.close()
                    self.__load_peer_certificate(cert_bytes)

    def __load_peer_certificate(self, cert_bytes):
        """Peer 인증서를 용도에 따라 메모리에 저장

        :param cert_bytes: 대상 인증서
        """
        x509cert = self.convert_x509cert_from_pem(cert_bytes)

        # Peer 인증서 발급을 위하여 가장 나중에 발급한 인증서 찾기
        serial = x509cert.serial_number
        if self.__LAST_PEER_INDEX < serial:
            self.__LAST_PEER_INDEX = serial

        subject = x509cert.subject
        cn = subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

        self.__PEER_CERT[cn] = x509cert

    @property
    def is_secure(self):
        return self.__ca_cert is not None and self.__ca_pri is not None

    def __save(self, cert_dir, cert_bytes, pri_bytes, ca_cert=None):
        """인증서/개인키 파일을 지정된 경로에 저장

        :param cert_dir: 저장 경로
        :param cert_bytes: 인증서
        :param pri_bytes: 개인키
        :param ca_cert: CA 인증서
        """
        logging.debug("Save Path : %s", cert_dir)

        if exists(cert_dir) is False:
            mkdir(cert_dir, mode=0o0755)
            logging.debug("Create CA Path : %s", cert_dir)
        else:
            # 디렉토리에 저장된 데이터 제거
            file_list = [f for f in listdir(cert_dir) if isfile(join(cert_dir, f))]
            for i in file_list:
                remove(join(cert_dir, i))

        cert_file = join(cert_dir, self.CERT_FILE)
        pri_file = join(cert_dir, self.PRI_FILE)

        f = open(cert_file, "wb")
        f.write(cert_bytes)
        f.close()
        logging.debug("Certificate(sign) saved : %s", cert_file)

        f = open(pri_file, "wb")
        f.write(pri_bytes)
        f.close()
        logging.debug("PrivateKey(sign) saved : %s", pri_file)

        if ca_cert is not None:
            ca_cert_file = join(cert_dir, self.PEER_CA_CERT_FILE)
            f = open(ca_cert_file, "wb")
            f.write(ca_cert)
            f.close()
            logging.debug("Certificate(CA) saved : %s", ca_cert_file)

    def convert_x509cert(self, cert_bytes):
        """바이너리 데이터를 x509 인증서로 변환

        :param cert_bytes: 인증서 bytes
        :return: x509 인증서
        """
        return x509.load_der_x509_certificate(cert_bytes, default_backend())

    def convert_x509cert_from_pem(self, cert_pem):
        """PEM 데이터를 x509 인증서로 변환
        
        :param cert_pem: PEM 인증서
        :return: x509 인증서
        """
        return x509.load_pem_x509_certificate(cert_pem, default_backend())

    def convert_privatekey(self, pri_bytes, password):
        """바이너리 데이터를 복호화하여 private_key 로 변환
        복호화 실패시 CA 인증서/개인키 None으로 설정

        :param pri_bytes: 개인키 bytes
        :param password: 개인키 복호화 비밀번호
        :return: private_key
        """
        try:
            return serialization.load_der_private_key(pri_bytes, password, default_backend())
        except ValueError:
            logging.debug("Invalid Password")
            self.__ca_cert = None
            self.__ca_pri = None
            return None

    def convert_privatekey_from_pem(self, pri_pem, password):
        """PEM 데이터를 복호화하여 private_key 로 변환
        복호화 실패시 CA 인증서/개인키 None으로 설정

        :param pri_pem: PEM 개인키
        :param password: 개인키 복호화 비밀번호
        :return: private_key
        """
        try:
            return serialization.load_pem_private_key(pri_pem, password, default_backend())
        except ValueError:
            logging.debug("Invalid Password")
            self.__ca_cert = None
            self.__ca_pri = None
            return None

    def verify_certificate(self, peer_cert):
        """
        인증서 검증
        :param peer_cert: 하위검증서
        :return: 검증내용
        """
        # 인증서 유효기간 검증
        not_after = peer_cert.not_valid_after
        now = datetime.datetime.now()
        if not_after < now:
            logging.error("Certificate is Expired")
            return False

        # 인증서 서명 검증
        ca_pub = self.__ca_cert.public_key()
        signature = peer_cert.signature
        data = peer_cert.tbs_certificate_bytes

        validation_result = False
        try:
            ca_pub.verify(
                signature=signature,
                data=data,
                signature_algorithm=ec.ECDSA(hashes.SHA256())
            )
            validation_result = True
        except InvalidSignature:
            logging.debug("InvalidSignatureException")

        return validation_result

    def sign_test(self):
        """인증서/개인키 로딩 후 서명 테스트

        :return: 테스트 결과(True/False)
        """
        if self.is_secure is False:
            logging.debug("CA is not secure_mode")
            return False

        data = b"test"
        signature = self.__ca_pri.sign(
            data,
            ec.ECDSA(hashes.SHA256())
        )
        try:
            pub_key = self.__ca_cert.public_key()
            pub_key.verify(
                signature,
                data,
                ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            logging.debug("cert test fail!!!")
            return False

    def generate_ca_cert(self, cn, ou, o, expire_period=None, password=None):
        """CA 인증서 생성
        Peer 인증서 발급 전용 인증서(ECC Key)

        :param cn: 주체 CommonName
        :param ou: 주체 OrganizationalUnitName
        :param o: 주체 OrganizationName
        :param expire_period: 인증서 유효기간(year)
        :param password: 개인키 암호화 비밀번호(8자리 이상)
        """
        sign_pri_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
        sign_pub_key = sign_pri_key.public_key()

        subject_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, o),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "kr")
        ])

        serial_number = self.__LAST_CA_INDEX + 1

        key_usage = x509.KeyUsage(digital_signature=True, content_commitment=False,
                                  key_encipherment=True, data_encipherment=False, key_agreement=False,
                                  key_cert_sign=True, crl_sign=False,
                                  encipher_only=False, decipher_only=False)

        if expire_period is None:
            expire_period = self.__ca_expired

        new_cert = self.__generate_cert(pub_key=sign_pub_key, subject_name=subject_name,
                                        issuer_name=subject_name, serial_number=serial_number,
                                        expire_period=expire_period, key_usage=key_usage,
                                        issuer_priv=sign_pri_key)

        cert_pem = new_cert.public_bytes(encoding=serialization.Encoding.PEM)
        if password is None:
            pri_pem = sign_pri_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        else:
            pri_pem = sign_pri_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(password=password)
            )

        self.__save(self.__CA_PATH, cert_pem, pri_pem)
        self.__LAST_CA_INDEX += 1
        self.__show_certificate(new_cert)

    def generate_peer_cert(self, cn, password=None):
        """Peer 인증서 생성
        서명용/암호화용 인증서(ECC Key), 유효기간은 1년

        :param cn: 주체 CommonName
        :param password: 개인키 암호화 비밀번호(8자리 이상)
        """
        pri_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
        pub_key = pri_key.public_key()

        issuer_name = self.__ca_cert.issuer
        ou = issuer_name.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value
        o = issuer_name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value

        subject_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, o),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "kr")
        ])

        expire_period = self.__peer_expired

        serial_number = self.__LAST_PEER_INDEX + 1

        key_usage = x509.KeyUsage(digital_signature=True, content_commitment=False,
                                  key_encipherment=True, data_encipherment=False, key_agreement=False,
                                  key_cert_sign=False, crl_sign=False,
                                  encipher_only=False, decipher_only=False)

        new_cert = self.__generate_cert(pub_key=pub_key, subject_name=subject_name,
                                        issuer_name=issuer_name, serial_number=serial_number,
                                        expire_period=expire_period, key_usage=key_usage,
                                        issuer_priv=self.__ca_pri, issuer_cert=self.__ca_cert)

        cert_pem = new_cert.public_bytes(encoding=serialization.Encoding.PEM)
        if password is None:
            pri_pem = pri_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        else:
            pri_pem = pri_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(password=password)
            )

        ca_cert_pem = self.__ca_cert.public_bytes(encoding=serialization.Encoding.PEM)

        peer_path = join(self.__DEFAULT_PATH, cn)
        self.__save(peer_path, cert_bytes=cert_pem, pri_bytes=pri_pem, ca_cert=ca_cert_pem)

        # 메모리에 추가
        self.__load_peer_certificate(cert_bytes=cert_pem)

        self.__show_certificate(new_cert)

    def __generate_cert(self, pub_key, subject_name, issuer_name, serial_number, expire_period, key_usage,
                        issuer_priv, issuer_cert=None):
        """인증서 생성

        :param pub_key: 공개키
        :param subject_name: 공개키 주체, x509.Name
        :param issuer_name: 발급 주체, x509.Name
        :param serial_number: 일련번호
        :param expire_period: 유효기간, year
        :param key_usage: 키 용도, x509.KeyUsage
        :param issuer_priv: 발급 개인키
        :return: 생성된 인증서
        """
        builder = x509.CertificateBuilder()

        # 주체 이름 설정
        builder = builder.subject_name(subject_name)

        # 발급자 이름 설정
        builder = builder.issuer_name(issuer_name)

        # 유효기간 설정
        date = datetime.datetime.now()
        builder = builder.not_valid_before(date)
        builder = builder.not_valid_after(date + datetime.timedelta(expire_period * 365, 0, 0))

        # 인증서 일련번호 설정
        builder = builder.serial_number(number=serial_number)

        # 공개키 설정
        builder = builder.public_key(key=pub_key)

        # 인증서 용도 설정
        builder = builder.add_extension(extension=key_usage, critical=True)

        # 주체 키 ID 설정
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key=pub_key), critical=False
        )

        # 확장 키 사용
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH, x509.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False
        )

        # 주체 대체 이름
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(self.__DOMAIN)]),
            critical=False
        )

        # 기관 키 ID 설정
        if issuer_cert is None:
            # CA 인증서(Self-Signed)
            if key_usage.key_cert_sign is True:
                builder = builder.add_extension(
                    x509.BasicConstraints(ca=True, path_length=None), critical=True
                )
        else:
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key=issuer_cert.public_key()), critical=False
            )

        # 인증서 생성(서명)
        return builder.sign(private_key=issuer_priv, algorithm=hashes.SHA256(), backend=default_backend())

    def show_ca_certificate(self):
        if self.__ca_cert is not None:
            self.__show_certificate(self.__ca_cert)
        else:
            logging.debug("CA Certificate is None")

    def show_peer_list(self):
        logging.debug("Last Serial Number : %s", self.__LAST_PEER_INDEX)
        cert_list = self.__PEER_CERT.keys()
        logging.debug("Sign Certificate list(%s)", len(cert_list))
        for cn in cert_list:
            self.__show_certificate(self.__PEER_CERT[cn])

    def __show_certificate(self, x509cert):
        extensions = x509cert.extensions
        key_usage = extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        if key_usage.digital_signature:
            logging.debug("----- certificate for digital signature -----")
        elif key_usage.key_encipherment or key_usage.key_agreement:
            logging.debug("----- certificate for encryption -----")
        elif key_usage.key_cert_sign or key_usage.crl_sign:
            logging.debug("----- CA certificate -----")

        issuer = x509cert.issuer
        subject = x509cert.subject
        serial = x509cert.serial_number
        not_after = x509cert.not_valid_after
        logging.debug("Subject       : %s", self.__print_x500_name(subject))
        logging.debug("Issuer        : %s", self.__print_x500_name(issuer))
        logging.debug("Serial Number : %s", serial)
        logging.debug("Not After     : %s", not_after)

    def __print_x500_name(self, name):
        cn = name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        ou = name.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value
        o = name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
        return "cn=" + cn + ", ou=" + ou + ", o=" + o + ", c=kr"

    def __get_x500_name_json(self, name):

        json_data = json.loads('{}')
        json_data['common_name'] = name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        json_data['organizational_unit'] = name.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value
        json_data['organization'] = name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
        json_data['country'] = 'kr'

        return json_data

    def get_ca_certificate(self):
        return self.__ca_cert

    def get_peer_certificate_list(self):
        return self.__PEER_CERT

    def get_peer_certificate(self, cn):
        return self.__PEER_CERT[cn]

    def get_certificate_json(self, x509cert):
        extensions = x509cert.extensions
        key_usage = extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value

        if key_usage.digital_signature:
            cert_type = CertificatePurpose.signature
        elif key_usage.key_encipherment or key_usage.key_agreement:
            cert_type = CertificatePurpose.encryption
        elif key_usage.key_cert_sign or key_usage.crl_sign:
            cert_type = CertificatePurpose.ca

        issuer = x509cert.issuer
        subject = x509cert.subject
        serial = x509cert.serial_number
        not_after = x509cert.not_valid_after
        cert_pem = x509cert.public_bytes(encoding=serialization.Encoding.PEM)

        json_data = json.loads('{}')
        json_data['cert_type'] = cert_type
        json_data['subject'] = self.__print_x500_name(subject)
        json_data['issuer'] = self.__print_x500_name(issuer)
        json_data['*serial_number'] = serial
        json_data['not_after'] = str(not_after)
        json_data['cert_pem'] = cert_pem.decode()

        return json_data
