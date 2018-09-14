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
"""Test CA service"""

import logging
import os
import unittest

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

import testcase.unittest.test_util as test_util
from loopchain.baseservice.ca_service import CAService
from loopchain.utils import loggers

loggers.set_preset_type(loggers.PresetType.develop)
loggers.update_preset()


class TestCAService(unittest.TestCase):

    __CERT_DIR = None
    __PASSWD = None

    def setUp(self):
        test_util.print_testname(self._testMethodName)
        self.__CERT_DIR = os.path.join(os.path.dirname(__file__), "../../resources/unittest")
        self.__PASSWD = None

    def tearDown(self):
        pass

    def test_ca_service(self):
        """CA 인증서 생성 및 검증
        """
        if os.path.exists(self.__CERT_DIR) is False:
            os.mkdir(self.__CERT_DIR, mode=0o0755)
            logging.debug("Create DEFAULT Path : %s", self.__CERT_DIR)

        # ########################## CA 인증서 신규 발급 시에만 아래 주석 제거 ########################
        ca = CAService(self.__CERT_DIR, self.__PASSWD)
        cn = "loopchain CA(1)"
        ou = "DEV"
        o = "theloop"
        period = 30

        logging.debug("New CA Certificate")
        ca.generate_ca_cert(cn=cn, ou=ou, o=o, expire_period=period, password=self.__PASSWD)
        # ####################################################################################

        new_ca = CAService(self.__CERT_DIR, self.__PASSWD)
        self.assertTrue(new_ca.sign_test())

    def test_peer_service(self):
        """2개 Peer 인증서 생성 후 테스트
        """
        ca = CAService(self.__CERT_DIR, self.__PASSWD)

        # 2개 Peer 인증서 생성
        for i in range(1, 2):
            cn = "TestPeer" + str(i)
            ca.generate_peer_cert(cn=cn, password=self.__PASSWD)

        # 생성된 인증서에 대한 검증
        validation_result = False
        for i in range(1, 2):
            cn = "TestPeer" + str(i)
            logging.debug("----- (%d)번째 인증서 검증 -----", i)
            validation_result = self.__test_certificate(cn, ca_servive=ca)
            logging.debug("----- (%d)번째 인증서 검증 결과 : %s -----", i, validation_result)
            if validation_result is False:
                break

        self.assertTrue(validation_result)

    def __test_certificate(self, name, ca_servive):
        """Peer별 인증서 검증 테스트

        :return 인증서 검증 결과(True/False)
        """
        cert_dir = os.path.join(self.__CERT_DIR, name)
        if os.path.exists(cert_dir):
            cert = self.__load_cert(cert_dir)
            if cert is None:
                logging.error("Sign Cert/key loading... Fail : %s", cert_dir)
                return False
            else:
                if ca_servive.verify_certificate(cert) is False:
                    logging.debug("Cerificate Validation Fail")
                    return False

            logging.debug("Certificate Validation Success")
            return True
        else:
            logging.debug("File Not Found(%s)", cert_dir)
            return False

    def __load_cert(self, cert_dir):
        """인증서/개인키 로딩 및 서명 테스트

        :param cert_dir: 인증서/개인키 파일 경로
        :return: X509 인증서
        """
        logging.debug("Cert/Key loading...")
        cert_file = os.path.join(cert_dir, "cert.pem")
        pri_file = os.path.join(cert_dir, "key.pem")

        f = open(cert_file, "rb")
        cert_bytes = f.read()
        f.close()
        cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())

        f = open(pri_file, "rb")
        pri_bytes = f.read()
        f.close()
        try:
            pri = serialization.load_pem_private_key(pri_bytes, self.__PASSWD, default_backend())
        except ValueError:
            logging.debug("Invalid Password(%s)", cert_dir)
            return None

        data = b"test"
        signature = pri.sign(data, ec.ECDSA(hashes.SHA256()))

        try:
            pub_key = cert.public_key()
            pub_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            return cert
        except InvalidSignature:
            logging.debug("sign test fail")
            return None


if __name__ == '__main__':
    unittest.main()
