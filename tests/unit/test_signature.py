import unittest
import os
import random
import tempfile
from asn1crypto import keys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from loopchain.crypto.signature import Signer, SignVerifier, long_to_bytes
from tests.unit import test_util


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

        cls.signer_private_key_bytes = Signer.from_prikey(cls.private_key_bytes)
        cls.signer_private_key_der = Signer.from_prikey_file(cls.private_der_path, b"TEST")
        cls.signer_private_key_pem = Signer.from_prikey_file(cls.private_pem_path, b"TEST")

        cls.sign_verifier_private_key_bytes = SignVerifier.from_prikey(cls.private_key_bytes)
        cls.sign_verifier_private_key_der = SignVerifier.from_prikey_file(cls.private_der_path, b"TEST")
        cls.sign_verifier_private_key_pem = SignVerifier.from_prikey_file(cls.private_pem_path, b"TEST")

        cls.sign_verifier_public_key_bytes = SignVerifier.from_pubkey(cls.public_key_bytes)
        cls.sign_verifier_public_key_der = SignVerifier.from_pubkey_file(cls.public_der_path)
        cls.sign_verifier_public_key_pem = SignVerifier.from_pubkey_file(cls.public_pem_path)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp_dir.cleanup()

    def setUp(self):
        test_util.print_testname(self._testMethodName)

    def test_signer_and_sign_verifier_hash_verification_success_result_equal(self):
        hash_data = os.urandom(32)
        signature = self.signer_private_key_bytes.sign_hash(hash_data)

        self.signer_private_key_bytes.verify_hash(hash_data, signature)
        self.signer_private_key_der.verify_hash(hash_data, signature)
        self.signer_private_key_pem.verify_hash(hash_data, signature)

        self.sign_verifier_private_key_bytes.verify_hash(hash_data, signature)
        self.sign_verifier_private_key_der.verify_hash(hash_data, signature)
        self.sign_verifier_private_key_pem.verify_hash(hash_data, signature)

        self.sign_verifier_public_key_bytes.verify_hash(hash_data, signature)
        self.sign_verifier_public_key_der.verify_hash(hash_data, signature)
        self.sign_verifier_public_key_pem.verify_hash(hash_data, signature)

    def test_signer_and_sign_verifier_data_verification_success_result_equal(self):
        data = os.urandom(random.randrange(1, 1000))
        signature = self.signer_private_key_bytes.sign_data(data)

        self.signer_private_key_bytes.verify_data(data, signature)
        self.signer_private_key_der.verify_data(data, signature)
        self.signer_private_key_pem.verify_data(data, signature)

        self.sign_verifier_private_key_bytes.verify_data(data, signature)
        self.sign_verifier_private_key_der.verify_data(data, signature)
        self.sign_verifier_private_key_pem.verify_data(data, signature)

        self.sign_verifier_public_key_bytes.verify_data(data, signature)
        self.sign_verifier_public_key_der.verify_data(data, signature)
        self.sign_verifier_public_key_pem.verify_data(data, signature)

    def test_signer_and_sign_verifier_hash_verification_failure_result_equal(self):
        hash_data = os.urandom(32)
        signature = self.signer_private_key_bytes.sign_hash(hash_data)
        invalid_signature0 = os.urandom(len(signature))
        invalid_signature1 = os.urandom(random.randrange(1, 1000))

        self.assertRaises(RuntimeError,
                          lambda: self.signer_private_key_bytes.verify_hash(hash_data, invalid_signature0))
        self.assertRaises(RuntimeError,
                          lambda: self.signer_private_key_bytes.verify_hash(hash_data, invalid_signature1))

        self.assertRaises(RuntimeError,
                          lambda: self.signer_private_key_der.verify_hash(hash_data, invalid_signature0))
        self.assertRaises(RuntimeError,
                          lambda: self.signer_private_key_der.verify_hash(hash_data, invalid_signature1))

        self.assertRaises(RuntimeError,
                          lambda: self.signer_private_key_pem.verify_hash(hash_data, invalid_signature0))
        self.assertRaises(RuntimeError,
                          lambda: self.signer_private_key_pem.verify_hash(hash_data, invalid_signature1))

        self.assertRaises(RuntimeError,
                          lambda: self.sign_verifier_private_key_bytes.verify_hash(hash_data, invalid_signature0))
        self.assertRaises(RuntimeError,
                          lambda: self.sign_verifier_private_key_bytes.verify_hash(hash_data, invalid_signature1))

        self.assertRaises(RuntimeError,
                          lambda: self.sign_verifier_private_key_der.verify_hash(hash_data, invalid_signature0))
        self.assertRaises(RuntimeError,
                          lambda: self.sign_verifier_private_key_der.verify_hash(hash_data, invalid_signature1))

        self.assertRaises(RuntimeError,
                          lambda: self.sign_verifier_private_key_pem.verify_hash(hash_data, invalid_signature0))
        self.assertRaises(RuntimeError,
                          lambda: self.sign_verifier_private_key_pem.verify_hash(hash_data, invalid_signature1))

        self.assertRaises(RuntimeError,
                          lambda: self.sign_verifier_public_key_bytes.verify_hash(hash_data, invalid_signature0))
        self.assertRaises(RuntimeError,
                          lambda: self.sign_verifier_public_key_bytes.verify_hash(hash_data, invalid_signature1))

        self.assertRaises(RuntimeError,
                          lambda: self.sign_verifier_public_key_der.verify_hash(hash_data, invalid_signature0))
        self.assertRaises(RuntimeError,
                          lambda: self.sign_verifier_public_key_der.verify_hash(hash_data, invalid_signature1))

        self.assertRaises(RuntimeError,
                          lambda: self.sign_verifier_public_key_pem.verify_hash(hash_data, invalid_signature0))
        self.assertRaises(RuntimeError,
                          lambda: self.sign_verifier_public_key_pem.verify_hash(hash_data, invalid_signature1))

    def test_signer_and_sign_verifier_data_verification_failure_result_equal(self):
        data = os.urandom(random.randrange(1, 1000))
        signature = self.signer_private_key_bytes.sign_data(data)
        invalid_signature0 = os.urandom(len(signature))
        invalid_signature1 = os.urandom(random.randrange(1, 1000))

        self.assertRaises(RuntimeError,
                          lambda: self.signer_private_key_bytes.verify_data(data, invalid_signature0))
        self.assertRaises(RuntimeError,
                          lambda: self.signer_private_key_bytes.verify_data(data, invalid_signature1))

        self.assertRaises(RuntimeError,
                          lambda: self.signer_private_key_der.verify_data(data, invalid_signature0))
        self.assertRaises(RuntimeError,
                          lambda: self.signer_private_key_der.verify_data(data, invalid_signature1))

        self.assertRaises(RuntimeError,
                          lambda: self.signer_private_key_pem.verify_data(data, invalid_signature0))
        self.assertRaises(RuntimeError,
                          lambda: self.signer_private_key_pem.verify_data(data, invalid_signature1))

        self.assertRaises(RuntimeError,
                          lambda: self.sign_verifier_private_key_bytes.verify_data(data, invalid_signature0))
        self.assertRaises(RuntimeError,
                          lambda: self.sign_verifier_private_key_bytes.verify_data(data, invalid_signature1))

        self.assertRaises(RuntimeError,
                          lambda: self.sign_verifier_private_key_der.verify_data(data, invalid_signature0))
        self.assertRaises(RuntimeError,
                          lambda: self.sign_verifier_private_key_der.verify_data(data, invalid_signature1))

        self.assertRaises(RuntimeError,
                          lambda: self.sign_verifier_private_key_pem.verify_data(data, invalid_signature0))
        self.assertRaises(RuntimeError,
                          lambda: self.sign_verifier_private_key_pem.verify_data(data, invalid_signature1))

        self.assertRaises(RuntimeError,
                          lambda: self.sign_verifier_public_key_bytes.verify_data(data, invalid_signature0))
        self.assertRaises(RuntimeError,
                          lambda: self.sign_verifier_public_key_bytes.verify_data(data, invalid_signature1))

        self.assertRaises(RuntimeError,
                          lambda: self.sign_verifier_public_key_der.verify_data(data, invalid_signature0))
        self.assertRaises(RuntimeError,
                          lambda: self.sign_verifier_public_key_der.verify_data(data, invalid_signature1))

        self.assertRaises(RuntimeError,
                          lambda: self.sign_verifier_public_key_pem.verify_data(data, invalid_signature0))
        self.assertRaises(RuntimeError,
                          lambda: self.sign_verifier_public_key_pem.verify_data(data, invalid_signature1))

    def test_hash_signatures_equal(self):
        hash_data = os.urandom(32)
        self.assertEquals(self.signer_private_key_bytes.sign_hash(hash_data),
                          self.signer_private_key_der.sign_hash(hash_data))
        self.assertEquals(self.signer_private_key_bytes.sign_hash(hash_data),
                          self.signer_private_key_pem.sign_hash(hash_data))

    def test_data_signatures_equal(self):
        data = os.urandom(random.randint(1, 1000))
        self.assertEquals(self.signer_private_key_bytes.sign_data(data),
                          self.signer_private_key_der.sign_data(data))
        self.assertEquals(self.signer_private_key_bytes.sign_data(data),
                          self.signer_private_key_pem.sign_data(data))

    def test_signer_private_keys_equal(self):
        self.assertEquals(self.signer_private_key_bytes.get_private_secret(),
                          self.signer_private_key_der.get_private_secret())
        self.assertEquals(self.signer_private_key_bytes.get_private_secret(),
                          self.signer_private_key_pem.get_private_secret())

    def test_signer_sign_verifier_addresses_equal(self):
        self.assertEquals(self.signer_private_key_bytes.address, self.signer_private_key_der.address)
        self.assertEquals(self.signer_private_key_bytes.address, self.signer_private_key_pem.address)

        self.assertEquals(self.sign_verifier_private_key_bytes.address, self.signer_private_key_bytes.address)
        self.assertEquals(self.sign_verifier_private_key_bytes.address, self.sign_verifier_private_key_der.address)
        self.assertEquals(self.sign_verifier_private_key_bytes.address, self.sign_verifier_private_key_pem.address)

        self.assertEquals(self.sign_verifier_public_key_bytes.address, self.signer_private_key_bytes.address)
        self.assertEquals(self.sign_verifier_public_key_bytes.address, self.sign_verifier_public_key_der.address)
        self.assertEquals(self.sign_verifier_public_key_bytes.address, self.sign_verifier_public_key_pem.address)

    def test_signer_from_pubkey(self):
        self.assertRaises(TypeError, lambda: Signer.from_pubkey(self.public_key_bytes))
        self.assertRaises(TypeError, lambda: Signer.from_pubkey_file(self.public_der_path))
        self.assertRaises(TypeError, lambda: Signer.from_pubkey_file(self.public_pem_path))
