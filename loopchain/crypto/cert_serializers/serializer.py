# Copyright 2019 ICON Foundation
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
import binascii
from abc import ABC, abstractmethod
from asn1crypto import keys
from typing import Optional
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


class Serializer(ABC):
    encoding = None

    @classmethod
    def serialize_private_key(cls, private_key: bytes, password=Optional[bytes]) -> bytes:
        pri_key = ec.derive_private_key(int.from_bytes(private_key, byteorder="big"),
                                        ec.SECP256K1,
                                        default_backend())
        algorithm = \
            serialization.BestAvailableEncryption(password) if password is not None else serialization.NoEncryption()
        return pri_key.private_bytes(encoding=cls.encoding,
                                     format=serialization.PrivateFormat.PKCS8,
                                     encryption_algorithm=algorithm)

    @classmethod
    def serialize_public_key(cls, public_key: bytes) -> bytes:
        public_numbers = ec.EllipticCurvePublicNumbers.from_encoded_point(ec.SECP256K1, public_key)
        pub_key = public_numbers.public_key(default_backend())
        return pub_key.public_bytes(encoding=cls.encoding,
                                    format=serialization.PublicFormat.SubjectPublicKeyInfo)

    @classmethod
    def deserialize_private_key(cls, cert_private_key: bytes, password=Optional[bytes]) -> bytes:
        temp_private = cls.load_private_key(cert_private_key, password, default_backend())
        no_pass_private = temp_private.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,  # It must be DER
            encryption_algorithm=serialization.NoEncryption()
        )
        key_info = keys.PrivateKeyInfo.load(no_pass_private)
        return long_to_bytes(key_info['private_key'].native['private_key'])

    @classmethod
    def deserialize_public_key(cls, cert_public_key: bytes) -> bytes:
        temp_public = cls.load_public_key(cert_public_key, default_backend())
        temp_public = temp_public.public_bytes(
            encoding=serialization.Encoding.DER,  # It must be DER
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        key_info = keys.PublicKeyInfo.load(temp_public)
        return key_info['public_key'].native

    @classmethod
    def serialize_private_key_file(cls, filename: str, private_key: bytes, password=Optional[bytes]):
        serialization_bytes = cls.serialize_private_key(private_key, password)
        with open(filename, "wb") as file:
            file.write(serialization_bytes)

    @classmethod
    def serialize_public_key_file(cls, filename: str, public_key: bytes):
        serialization_bytes = cls.serialize_public_key(public_key)
        with open(filename, "wb") as file:
            file.write(serialization_bytes)

    @classmethod
    def deserialize_private_key_file(cls, cert_filename: str, password=Optional[bytes]) -> bytes:
        with open(cert_filename, "rb") as file:
            serialization_bytes = file.read()
        return cls.deserialize_private_key(serialization_bytes, password)

    @classmethod
    def deserialize_public_key_file(cls, cert_filename: str) -> bytes:
        with open(cert_filename, "rb") as file:
            serialization_bytes = file.read()
        return cls.deserialize_public_key(serialization_bytes)

    @classmethod
    @abstractmethod
    def load_private_key(cls, cert_private_key: bytes, password, backend):
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def load_public_key(cls, cert_public_key: bytes, backend):
        raise NotImplementedError


def long_to_bytes(val, endianness='big'):
    """
    Use :ref:`string formatting` and :func:`~binascii.unhexlify` to
    convert ``val``, a :func:`long`, to a byte :func:`str`.

    :param long val: The value to pack

    :param str endianness: The endianness of the result. ``'big'`` for
      big-endian, ``'little'`` for little-endian.

    If you want byte- and word-ordering to differ, you're on your own.

    Using :ref:`string formatting` lets us use Python's C innards.
    """

    # one (1) hex digit per four (4) bits
    width = val.bit_length()

    # unhexlify wants an even multiple of eight (8) bits, but we don't
    # want more digits than we need (hence the ternary-ish 'or')
    width += 8 - ((width % 8) or 8)

    # format width specifier: four (4) bits per hex digit
    fmt = '%%0%dx' % (width // 4)

    # prepend zero (0) to the width, to zero-pad the output
    s = binascii.unhexlify(fmt % val)

    if endianness == 'little':
        # see http://stackoverflow.com/a/931095/309233
        s = s[::-1]

    return s
