import unittest
import os
import tempfile
from asn1crypto import keys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from loopchain.utils import loggers
from loopchain.crypto.signature import Signer, SignVerifier, long_to_bytes
from testcase.unittest import test_util

loggers.set_preset_type(loggers.PresetType.develop)
loggers.update_preset()


class TestSignature(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp_dir = tempfile.TemporaryDirectory()

        # Private Key
        cls.private_key = ec.generate_private_key(ec.SECP256K1, default_backend())

        cls.private_der_path = os.path.join(cls.temp_dir.name, "private.der")
        with open(cls.private_der_path, "wb") as private_der_file:
            private_der_file.write(
                cls.private_key.private_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(b"TEST")
                )
            )

        cls.private_pem_path = os.path.join(cls.temp_dir.name, "private.pem")
        with open(cls.private_pem_path, "wb") as private_pem_file:
            private_pem_file.write(
                cls.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(b"TEST")
                )
            )

        key_info = keys.PrivateKeyInfo.load(cls.private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
        cls.private_key_bytes = long_to_bytes(key_info['private_key'].native['private_key'])

        # Public Key
        cls.public_key = cls.private_key.public_key()

        cls.public_der_path = os.path.join(cls.temp_dir.name, "public.der")
        with open(cls.public_der_path, "wb") as public_der_file:
            public_der_file.write(
                cls.public_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

        cls.public_pem_path = os.path.join(cls.temp_dir.name, "public.pem")
        with open(cls.public_pem_path, "wb") as public_pem_file:
            public_pem_file.write(
                cls.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

        key_info = keys.PublicKeyInfo.load(
            cls.public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
        cls.public_key_bytes = key_info['public_key'].native

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp_dir.cleanup()

    def setUp(self):
        test_util.print_testname(self._testMethodName)

    def test_sign_and_verify_hash(self):
        signer = Signer.from_prikey(self.private_key_bytes)
        sign_verifier = SignVerifier.from_pubkey(self.public_key_bytes)

        hash_data = os.urandom(32)
        signature = signer.sign_hash(hash_data)

        signer.verify_hash(hash_data, signature)
        sign_verifier.verify_hash(hash_data, signature)

    def test_sign_and_verify_data(self):
        signer = Signer.from_prikey(self.private_key_bytes)
        sign_verifier = SignVerifier.from_pubkey(self.public_key_bytes)

        data = b"ANYTHING YOU WANT"
        signature = signer.sign_data(data)

        signer.verify_data(data, signature)
        sign_verifier.verify_data(data, signature)

    def test_signer_private_key_equal(self):
        signer_bytes = Signer.from_prikey(self.private_key_bytes)
        signer_der = Signer.from_prikey_file(self.private_der_path, b"TEST")
        signer_pem = Signer.from_prikey_file(self.private_pem_path, b"TEST")

        self.assertEquals(signer_bytes._private_key.private_key, signer_der._private_key.private_key)
        self.assertEquals(signer_bytes._private_key.private_key, signer_pem._private_key.private_key)

    def test_signer_sign_verifier_address_equal(self):
        signer_private_key_bytes = Signer.from_prikey(self.private_key_bytes)
        signer_private_key_der = Signer.from_prikey_file(self.private_der_path, b"TEST")
        signer_private_key_pem = Signer.from_prikey_file(self.private_pem_path, b"TEST")

        self.assertEquals(signer_private_key_bytes.address, signer_private_key_der.address)
        self.assertEquals(signer_private_key_bytes.address, signer_private_key_pem.address)

        sign_verifier_private_key_bytes = SignVerifier.from_prikey(self.private_key_bytes)
        sign_verifier_private_key_der = SignVerifier.from_prikey_file(self.private_der_path, b"TEST")
        sign_verifier_private_key_pem = SignVerifier.from_prikey_file(self.private_pem_path, b"TEST")

        self.assertEquals(sign_verifier_private_key_bytes.address, signer_private_key_bytes.address)
        self.assertEquals(sign_verifier_private_key_bytes.address, sign_verifier_private_key_der.address)
        self.assertEquals(sign_verifier_private_key_bytes.address, sign_verifier_private_key_pem.address)

        sign_verifier_public_key_bytes = SignVerifier.from_pubkey(self.public_key_bytes)
        sign_verifier_public_key_der = SignVerifier.from_pubkey_file(self.public_der_path)
        sign_verifier_public_key_pem = SignVerifier.from_pubkey_file(self.public_pem_path)

        self.assertEquals(sign_verifier_public_key_bytes.address, signer_private_key_bytes.address)
        self.assertEquals(sign_verifier_public_key_bytes.address, sign_verifier_public_key_der.address)
        self.assertEquals(sign_verifier_public_key_bytes.address, sign_verifier_public_key_pem.address)

    def test_signer_from_pubkey(self):
        self.assertRaises(TypeError, lambda: Signer.from_pubkey(self.public_key_bytes))
        self.assertRaises(TypeError, lambda: Signer.from_pubkey_file(self.public_der_path))
        self.assertRaises(TypeError, lambda: Signer.from_pubkey_file(self.public_pem_path))
