#!/usr/bin/env python
# -*- coding: utf-8 -*-

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
"""Test Crypto functions"""

import base64
import copy
import datetime
import hashlib
import json
import logging
import unittest

import OpenSSL
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.x509.oid import NameOID

from loopchain import configure as conf
from loopchain.utils import loggers
from loopchain.blockchain.hashing import (get_tx_hash_generator, build_hash_generator,
                                          HashPreprocessor, HashPreprocessorSendTransaction)

import testcase.unittest.test_util as test_util

loggers.set_preset_type(loggers.PresetType.develop)
loggers.update_preset()


class TestCrypto(unittest.TestCase):

    def setUp(self):
        test_util.print_testname(self._testMethodName)

        self.hash_generator = get_tx_hash_generator(conf.LOOPCHAIN_DEFAULT_CHANNEL)

    def tearDown(self):
        pass

    def test_ecc_key(self):
        """
        ECC 키쌍을 생성하여 인증서 생성, ECDSA 서명/검증 테스트
        """
        logging.debug("----- ECDSA Test Start -----")
        # 키쌍 생성
        pri_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
        pub_key = pri_key.public_key()

        pri_der = pri_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            # encryption_algorithm=serialization.NoEncryption()
            encryption_algorithm=serialization.BestAvailableEncryption(password=b'qwer1234')
        )

        pub_der = pub_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        pri_b64 = base64.b64encode(pri_der, altchars=None)
        pub_b64 = base64.b64encode(pub_der, altchars=None)

        logging.debug("Private Key : \n%s", pri_b64)
        logging.debug("Public  Key : \n%s", pub_b64)

        # 인증서 생성
        cert = self._generate_cert(pub_key=pub_key, issuer_key=pri_key, subject_name="test")
        cert_key = cert.public_key()

        # ECDSA 서명 생성 및 검증 테스트
        data = b"test"
        signature = self._generate_sign(pri_key=pri_key, data=data)

        sign_b64 = base64.b64encode(signature, altchars=None)
        logging.debug("Sign : %s", sign_b64)

        validation_result = self._verify_signature(pub_key=cert_key, data=data, signature=signature)
        logging.debug("Verify : %s", validation_result)
        self.assertEqual(validation_result, True)

        # ECDSA 서명을 생성하는 다른 방법
        signature = pri_key.sign(
            data,
            ec.ECDSA(hashes.SHA256())
        )

        validation_result = self._verify_signature(pub_key=cert_key, data=data, signature=signature)
        logging.debug("----- ECDSA Test End -----\n")
        self.assertTrue(validation_result)

    def test_rsa_key(self):
        """
        RSA 키쌍을 생성하여 인증서 생성, RSA 서명/검증 테스트
        :return:
        """
        logging.debug("----- RSA Test Start -----")
        # 키 쌍 생성
        pri_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        pub_key = pri_key.public_key()

        pri_der = pri_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        pub_der = pub_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        pri_b64 = base64.b64encode(pri_der, altchars=None)
        pub_b64 = base64.b64encode(pub_der, altchars=None)

        logging.debug("Private Key : \n%s", pri_b64)
        logging.debug("Public  Key : \n%s", pub_b64)

        # 인증서 생성
        cert = self._generate_cert(pub_key=pub_key, issuer_key=pri_key, subject_name="test")
        cert_key = cert.public_key()

        # RSA 서명 생성 및 검증 테스트
        data = b"test"
        signature = self._generate_sign(pri_key=pri_key, data=data)
        sign_b64 = base64.b64encode(signature, altchars=None)
        logging.debug("Sign : %s", sign_b64)

        validation_result = self._verify_signature(pub_key=cert_key, data=data, signature=signature)

        logging.debug("----- RSA Test End -----\n")
        self.assertTrue(validation_result)

    def test_pkcs12_format(self):
        """
        PKCS12 형식으로 인증서/개인키 저장을 위한 코드
        """
        logging.debug("----- PKCS12 Test Start -----")
        # ECC 키 쌍 생성
        pri_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
        pub_key = pri_key.public_key()

        logging.debug("Key_Type : %s", type(pri_key))

        # 인증서 생성
        cert = self._generate_cert(pub_key=pub_key, issuer_key=pri_key, subject_name="test")

        cert_pem = cert.public_bytes(
            encoding=serialization.Encoding.DER
        )
        key_pem = pri_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # 인증서/개인키를 OpenSSL Key로 변환
        crypto = OpenSSL.crypto
        cert_ssl_key = crypto.load_certificate(
            type=crypto.FILETYPE_ASN1,
            buffer=cert_pem
        )
        priv_ssl_key = crypto.load_privatekey(
            type=crypto.FILETYPE_ASN1,
            buffer=key_pem,
            passphrase=None
        )

        logging.debug("Key_Type : %s", type(priv_ssl_key))

        # 변환한 인증서개인키를 PKCS12형식으로 변환
        p12 = OpenSSL.crypto.PKCS12()
        p12.set_privatekey(priv_ssl_key)
        p12.set_certificate(cert_ssl_key)
        pfx = p12.export()

        pfx_b64 = base64.b64encode(pfx, altchars=None)
        logging.debug("%s", pfx_b64)

    def _generate_cert(self, pub_key, issuer_key, subject_name):
        """
        서명용 인증서 생성

        :param pub_key: 공개키
        :param issuer_key: 인증서 생성용 발급자 개인키
        :param subject_name: 생성될 인증서 주체명
        :return: 인증서
        """
        builder = x509.CertificateBuilder()
        # 주체 이름 설정
        builder = builder.subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Theloop CA"),
                x509.NameAttribute(NameOID.COUNTRY_NAME, "kr")
            ])
        )

        # 발급자 이름 설정
        builder = builder.issuer_name(
            x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Theloop CA"),
                x509.NameAttribute(NameOID.COUNTRY_NAME, "kr")
            ])
        )

        # 유효기간 설정
        builder = builder.not_valid_before(datetime.datetime.today())
        builder = builder.not_valid_after(datetime.datetime.today() + datetime.timedelta(1, 0, 0))

        # 인증서 일련번호 설정
        builder = builder.serial_number(1)

        # 공개키 설정
        builder = builder.public_key(pub_key)

        # 인증서 용도 설정(서명용)
        builder = builder.add_extension(
            x509.KeyUsage(digital_signature=True, content_commitment=True,
                          key_encipherment=False, data_encipherment=False, key_agreement=False,
                          key_cert_sign=False, crl_sign=False,
                          encipher_only=False, decipher_only=False),
            critical=True
        )

        # 인증서 생성(서명)
        cert = builder.sign(
            private_key=issuer_key,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )

        cert_der = cert.public_bytes(
            encoding=serialization.Encoding.DER
        )

        cert_b64 = base64.b64encode(cert_der, altchars=None)
        logging.debug("Certificate : %s", cert_b64)

        # 생성된 인증서에 포함된 서명을 추출하여 검증
        # 생성된 인증서는 Self-Signed 인증서이므로 인증서에 포함된 공개키를 이용하여 검증
        cert_sign = cert.signature
        cert_data = cert.tbs_certificate_bytes
        if self._verify_cert_signature(pub_key=cert.public_key(), data=cert_data, signature=cert_sign):
            logging.debug("Certificate Signature Validation Success")
        else:
            logging.debug("Certificate Signature Validation Fail")
            return None

        return cert

    def _generate_sign(self, pri_key, data):
        """
        서명 데이터 생성

        :param pri_key: 서명용 개인키
        :param data: 서명 원문 데이터
        :return: 생성된 서명 데이터
        """
        _signature = None
        # 개인키의 Type(RSA, ECC)에 따라 서명 방식 분리
        if isinstance(pri_key, ec.EllipticCurvePrivateKeyWithSerialization):
            # ECDSA 서명
            logging.debug("Sign ECDSA")

            signer = pri_key.signer(ec.ECDSA(hashes.SHA256()))
            signer.update(data)
            _signature = signer.finalize()
        elif isinstance(pri_key, rsa.RSAPrivateKeyWithSerialization):
            # RSA 서명
            logging.debug("Sign RSA")

            _signature = pri_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        else:
            logging.debug("Unknown PrivateKey Type : %s", type(pri_key))

        return _signature

    def _verify_signature(self, pub_key, data, signature):
        """
        서명 데이터 검증

        :param pub_key: 검증용 공개키
        :param data: 서명 원문 데이터
        :param signature: 서명 데이터
        :return: 서명 검증 결과(True/False)
        """
        validation_result = False
        # 공개키의 Type(RSA, ECC)에 따라 검증 방식 분리
        if isinstance(pub_key, ec.EllipticCurvePublicKeyWithSerialization):
            # ECDSA 서명
            logging.debug("Verify ECDSA")

            try:
                pub_key.verify(
                    signature,
                    data,
                    ec.ECDSA(hashes.SHA256())
                )
                validation_result = True
            except InvalidSignature:
                logging.debug("InvalidSignature_ECDSA")
        elif isinstance(pub_key, rsa.RSAPublicKeyWithSerialization):
            # RSA 서명
            logging.debug("Verify RSA")

            try:
                pub_key.verify(
                    signature,
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                validation_result = True
            except InvalidSignature:
                logging.debug('InvalidSignature_RSA')

        else:
            logging.debug("Unknown PublicKey Type : %s", type(pub_key))

        return validation_result

    def _verify_cert_signature(self, pub_key, data, signature):
        """
        인증서에 포함된 서명 검증

        :param pub_key: 인증서 발급자의 공개키
        :param data: 인증서 내의 서명 원문 데이터(TBSCertificate)
        :param signature: 인증서 내의 서명 데이터
        :return: 서명 검증 결과(True/False)
        """
        validation_result = False
        # 공개키의 Type(RSA, ECC)에 따라 검증 방식 분리
        # 인증서 서명의 경우 AlgorithmOID에 따라서 판단해야 하지만
        # 파이선 라이브러리에서 사용하는 알고리즘으로 고정
        if isinstance(pub_key, ec.EllipticCurvePublicKeyWithSerialization):
            # ECDSA 서명
            logging.debug("Verify ECDSA")

            try:
                pub_key.verify(
                    signature,
                    data,
                    ec.ECDSA(hashes.SHA256())
                )
                validation_result = True
            except InvalidSignature:
                logging.debug("InvalidSignature_ECDSA")
        elif isinstance(pub_key, rsa.RSAPublicKeyWithSerialization):
            # RSA 서명
            logging.debug("Verify RSA")

            try:
                # 데이터 서명할 때와는 Padding 방식이 다름
                pub_key.verify(
                    signature,
                    data,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                validation_result = True
            except InvalidSignature:
                logging.debug('InvalidSignature_RSA')

        else:
            logging.debug("Unknown PublicKey Type : %s", type(pub_key))

        return validation_result

    def test_hash_origin_case_v2(self):
        request = r'''{
            "jsonrpc": "2.0",
            "method": "icx_sendTransaction",
            "id": 1234,
            "params": {
                "version": "0x3",
                "from": "hxbe258ceb872e08851f1f59694dac2558708ece11",
                "to": "hx5bfdb090f43a808005ffc27c25b213145e80b7cd",
                "value": "0xde0b6b3a7640000",
                "timestamp": "0x563a6cf330136",
                "nonce": "0x1",
                "signature": "VAia7YZ2Ji6igKWzjR2YsGa2m53nKPrfK7uXYW78QLE+ATehAVZPC40szvAiA6NEU5gCYB4c4qaQzqDh2ugcHgA="
            }
        }'''

        logging.info(f"request : {request}")
        request = json.loads(request)
        logging.info(f"request loaded : {request}")

        question = request["params"]
        answer = "icx_sendTransaction.from.hxbe258ceb872e08851f1f59694dac2558708ece11.nonce.0x1." \
                 "timestamp.0x563a6cf330136.to.hx5bfdb090f43a808005ffc27c25b213145e80b7cd." \
                 "value.0xde0b6b3a7640000.version.0x3"

        result = self.hash_generator.generate_salted_origin(question)
        self.assertEqual(result, answer)

    def test_hash_origin_case_v3(self):
        request = '''{
            "jsonrpc": "2.0",
            "method": "icx_sendTransaction",
            "id": 1234,
            "params": {
                "version": "0x3",
                "from": "hxbe258ceb872e08851f1f59694dac2558708ece11",
                "to": "cxb0776ee37f5b45bfaea8cff1d8232fbb6122ec32",
                "stepLimit": "0x12345",
                "timestamp": "0x563a6cf330136",
                "nonce": "0x1",
                "signature": "VAia7YZ2Ji6igKWzjR2YsGa2m53nKPrfK7uXYW78QLE+ATehAVZPC40szvAiA6NEU5gCYB4c4qaQzqDh2ugcHgA=",
                "dataType": "call",
                "data": {
                    "method": "transfer",
                    "params": {
                        "to": "hxab2d8215eab14bc6bdd8bfb2c8151257032ecd8b",
                        "value": "0x1",
                        "array0": [
                            "1",
                            "221"
                        ],
                        "array1": [
                            {
                                "hash": "0x12",
                                "value": "0x34"
                            },
                            {
                                "hash": "0x56",
                                "value": "0x78"
                            }
                        ]
                    }
                }
            }
        }'''

        logging.info(f"request : {request}")
        request = json.loads(request)
        logging.info(f"request loaded : {request}")

        question = request["params"]
        answer = "icx_sendTransaction.data.{method.transfer.params." \
                 "{array0.[1.221].array1.[{hash.0x12.value.0x34}.{hash.0x56.value.0x78}]." \
                 "to.hxab2d8215eab14bc6bdd8bfb2c8151257032ecd8b.value.0x1}}." \
                 "dataType.call.from.hxbe258ceb872e08851f1f59694dac2558708ece11.nonce.0x1.stepLimit.0x12345." \
                 "timestamp.0x563a6cf330136.to.cxb0776ee37f5b45bfaea8cff1d8232fbb6122ec32.version.0x3"

        result = self.hash_generator.generate_salted_origin(question)
        self.assertEqual(result, answer)

    def test_hash_case_v3_escape(self):
        request = r'''{
            "jsonrpc": "2.0",
            "method": "icx_sendTransaction",
            "id": 1234,
            "params": {
                "version": "0x3",
                "from": "hxbe258ceb872e08851f1f59694dac2558708ece11",
                "to": "cxb0776ee37f5b45bfaea8cff1d8232fbb6122ec32",
                "stepLimit": "0x12345",
                "timestamp": "0x563a6cf330136",
                "nonce": "0x1",
                "signature": "VAia7YZ2Ji6igKWzjR2YsGa2m53nKPrfK7uXYW78QLE+ATehAVZPC40szvAiA6NEU5gCYB4c4qaQzqDh2ugcHgA=",
                "dataType": "call",
                "data": {
                    "method": "transfer",
                    "params": {
                        "to": "hx.ab2d8215eab\\14bc6bdd8bfb2c[8151257]032ec{d8}b",
                        "value": "0x1",
                        "array0": [
                            "1",
                            "2.21"
                        ],
                        "array1": [
                            {
                                "hash": "0x12",
                                "value": "0x34"
                            },
                            {
                                "hash": "0x56",
                                "value": "0x78"
                            }
                        ]
                    }
                }
            }
        }'''

        logging.info(f"request : {request}")
        request = json.loads(request)
        logging.info(f"request loaded : {request}")
        logging.info(f"to : {request['params']['data']['params']['to']}")

        question = request['params']
        answer = r"icx_sendTransaction.data.{method.transfer.params." \
                 r"{array0.[1.2\.21].array1.[{hash.0x12.value.0x34}.{hash.0x56.value.0x78}]." \
                 r"to.hx\.ab2d8215eab\\14bc6bdd8bfb2c\[8151257\]032ec\{d8\}b.value.0x1}}." \
                 r"dataType.call.from.hxbe258ceb872e08851f1f59694dac2558708ece11.nonce.0x1.stepLimit.0x12345." \
                 r"timestamp.0x563a6cf330136.to.cxb0776ee37f5b45bfaea8cff1d8232fbb6122ec32.version.0x3"

        result = self.hash_generator.generate_salted_origin(question)
        logging.info(f"result : {result}")
        self.assertEqual(result, answer)

    def test_hash_case_v3_null(self):
        request = r'''{
            "jsonrpc": "2.0",
            "method": "icx_sendTransaction",
            "id": 1234,
            "params": {
                "version": "0x3",
                "from": "hxbe258ceb872e08851f1f59694dac2558708ece11",
                "to": "cxb0776ee37f5b45bfaea8cff1d8232fbb6122ec32",
                "stepLimit": "0x12345",
                "timestamp": "0x563a6cf330136",
                "nonce": "0x1",
                "signature": "VAia7YZ2Ji6igKWzjR2YsGa2m53nKPrfK7uXYW78QLE+ATehAVZPC40szvAiA6NEU5gCYB4c4qaQzqDh2ugcHgA=",
                "dataType": "call",
                "data": {
                    "method": "transfer",
                    "params": {
                        "to": "hxab2d8215eab14bc6bdd8bfb2c8151257032ecd8b",
                        "value": "0x1",
                        "array0": [
                            null,
                            null
                        ],
                        "array1": [
                            {
                                "hash": null,
                                "value": null
                            },
                            {
                                "hash": null,
                                "value": "0x78"
                            }
                        ]
                    }
                }
            }
        }'''

        logging.info(f"request : {request}")
        request = json.loads(request)
        logging.info(f"request loaded : {request}")

        question = request["params"]
        answer = r"icx_sendTransaction.data.{method.transfer.params." \
                 r"{array0.[\0.\0].array1.[{hash.\0.value.\0}.{hash.\0.value.0x78}]." \
                 r"to.hxab2d8215eab14bc6bdd8bfb2c8151257032ecd8b.value.0x1}}." \
                 r"dataType.call.from.hxbe258ceb872e08851f1f59694dac2558708ece11.nonce.0x1.stepLimit.0x12345." \
                 r"timestamp.0x563a6cf330136.to.cxb0776ee37f5b45bfaea8cff1d8232fbb6122ec32.version.0x3"

        result = self.hash_generator.generate_salted_origin(question)
        logging.info(f"result : {result}")
        self.assertEqual(result, answer)

    def test_hash_case_v2_v3_compatibility(self):

        # These methods are obsolete.
        # But this one and new one must have same results for v2 request.
        def create_origin_for_hash(json_data: dict):
            def gen_origin_str(json_data: dict):
                ordered_keys = list(json_data)
                ordered_keys.sort()
                for key in ordered_keys:
                    yield key
                    if isinstance(json_data[key], str):
                        yield json_data[key]
                    elif isinstance(json_data[key], dict):
                        yield from gen_origin_str(json_data[key])
                    elif isinstance(json_data[key], int):
                        yield str(json_data[key])
                    else:
                        raise TypeError(f"{key} must be one of them(dict, str, int).")

            origin = ".".join(gen_origin_str(json_data))
            return origin

        def generate_icx_hash(icx_origin_data, tx_hash_key):
            copy_tx = copy.deepcopy(icx_origin_data)
            if 'method' in copy_tx:
                del copy_tx['method']
            if 'signature' in copy_tx:
                del copy_tx['signature']
            if tx_hash_key in copy_tx:
                del copy_tx[tx_hash_key]
            origin = create_origin_for_hash(copy_tx)
            origin = f"icx_sendTransaction.{origin}"
            # gen hash
            return hashlib.sha3_256(origin.encode()).hexdigest()

        request = r'''{
            "jsonrpc": "2.0",
            "method": "icx_sendTransaction",
            "id": 1234,
            "params": {
                "version": "0x3",
                "from": "hxbe258ceb872e08851f1f59694dac2558708ece11",
                "to": "hx5bfdb090f43a808005ffc27c25b213145e80b7cd",
                "value": "0xde0b6b3a7640000",
                "timestamp": "0x563a6cf330136",
                "nonce": "0x1",
                "signature": "VAia7YZ2Ji6igKWzjR2YsGa2m53nKPrfK7uXYW78QLE+ATehAVZPC40szvAiA6NEU5gCYB4c4qaQzqDh2ugcHgA="
            }
        }'''

        logging.info(f"request : {request}")
        request = json.loads(request)
        logging.info(f"request loaded : {request}")

        question = request["params"]

        result_new_hash = self.hash_generator.generate_hash(question)
        result_old_hash = generate_icx_hash(question, "tx_hash")
        self.assertEqual(result_new_hash, result_old_hash)

        v0_hash_generator = build_hash_generator(0, HashPreprocessorSendTransaction(), "icx_sendTransaction")
        result_old_hash = v0_hash_generator.generate_hash(question)

        self.assertEquals(result_new_hash, result_old_hash)

    def test_genesis_hash_compatibility(self):
        genesis_init_data = {
            "transaction_data": {
                "accounts": [
                    {
                        "name": "god",
                        "address": "hxebf3a409845cd09dcb5af31ed5be5e34e2af9433",
                        "balance": "0x2961ffa20dd47f5c4700000"
                    },
                    {
                        "name": "treasury",
                        "address": "hxd5775948cb745525d28ec8c1f0c84d73b38c78d4",
                        "balance": "0x0"
                    },
                    {
                        "name": "test1",
                        "address": "hx670e692ffd3d5587c36c3a9d8442f6d2a8fcc795",
                        "balance": "0x0"
                    },
                    {
                        "name": "test2",
                        "address": "hxdc8d79453ba6516bc140b7f53b6b9a012da7ff10",
                        "balance": "0x0"
                    },
                    {
                        "name": "test3",
                        "address": "hxbedeeadea922dc7f196e22eaa763fb01aab0b64c",
                        "balance": "0x0"
                    },
                    {
                        "name": "test4",
                        "address": "hxa88d8addc6495e4c21b0dda5b0bf6c9108c98da6",
                        "balance": "0x0"
                    },
                    {
                        "name": "test5",
                        "address": "hx0260cc5b8777485b04e9dc938b1ee949910f41e1",
                        "balance": "0x0"
                    },
                    {
                        "name": "test6",
                        "address": "hx09e89b468a1cdfdd24441668204911502fa3add9",
                        "balance": "0x0"
                    },
                    {
                        "name": "test7",
                        "address": "hxeacd884f0e0b5b2e4a6b4ee87fa5184ab9f25cbe",
                        "balance": "0x0"
                    },
                    {
                        "name": "test8",
                        "address": "hxa943122f57c7c2af7416c1f2e1af46838ad0958f",
                        "balance": "0x0"
                    },
                    {
                        "name": "test9",
                        "address": "hxc0519e1c56030be070afc89fbf05783c89b15e2f",
                        "balance": "0x0"
                    },
                    {
                        "name": "test10",
                        "address": "hxcebc788d5b922b356a1dccadc384d36964e87165",
                        "balance": "0x0"
                    },
                    {
                        "name": "test11",
                        "address": "hx7f8f432ffdb5fc1d2df6dd452ca52eb719150f3c",
                        "balance": "0x0"
                    },
                    {
                        "name": "test12",
                        "address": "hxa6c4468032824092ecdb3de2bb66947d69e07b59",
                        "balance": "0x0"
                    },
                    {
                        "name": "test13",
                        "address": "hxc26d0b28b11732b38c0a2c0634283730258f272a",
                        "balance": "0x0"
                    },
                    {
                        "name": "test14",
                        "address": "hx695ddb2d1e78f012e3e271e95ffbe4cc8fcd133b",
                        "balance": "0x0"
                    },
                    {
                        "name": "test15",
                        "address": "hx80ab6b11b5d5c80448d011d10fb1a579c57e0a6c",
                        "balance": "0x0"
                    },
                    {
                        "name": "test16",
                        "address": "hxa9c7881a53f2245ed12238412940c6f54874c4e3",
                        "balance": "0x0"
                    },
                    {
                        "name": "test17",
                        "address": "hx4e53cffe116baaff5e1940a6a0c14ad54f7534f2",
                        "balance": "0x0"
                    },
                    {
                        "name": "test18",
                        "address": "hxbbef9e3942d3d5d83b5293b3cbc20940b459e3eb",
                        "balance": "0x0"
                    }
                ],
                "message": "A rHizomE has no beGInning Or enD; it is alWays IN the miDDle, between tHings, interbeing, intermeZzO. ThE tree is fiLiatioN, but the rhizome is alliance, uniquelY alliance. The tree imposes the verb \"to be\" but the fabric of the rhizome is the conJUNction, \"AnD ... and ...and...\"THis conJunction carriEs enouGh force to shaKe and uproot the verb \"to be.\" Where are You goIng? Where are you coMing from? What are you heading for? These are totally useless questions.\n\n- 『Mille Plateaux』, Gilles Deleuze & Felix Guattari\n\n\"Hyperconnect the world\""
            }
        }

        genesis_hash_generator = build_hash_generator(0, HashPreprocessor(), "genesis_tx")
        genesis_tx_hash = genesis_hash_generator.generate_hash(genesis_init_data["transaction_data"])
        self.assertEqual(genesis_tx_hash, "6dbc389370253739f28b8c236f4e7acdcfcdb9cfe8386c32d809114d5b00ac65")


if __name__ == '__main__':
    unittest.main()
