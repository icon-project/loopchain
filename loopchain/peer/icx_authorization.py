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
""" A class for icx authorization of Peer"""

import binascii
import hashlib
import logging
from asn1crypto import keys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from secp256k1 import PrivateKey

import loopchain.utils as util
from loopchain import configure as conf
from loopchain.tools.signature_helper import PublicVerifier, IcxVerifier


def long_to_bytes (val, endianness='big'):
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


class IcxAuthorization(IcxVerifier):
    def __init__(self, channel):
        super().__init__()
        self.__channel = channel
        with open(conf.CHANNEL_OPTION[self.__channel][PublicVerifier.PRIVATE_PATH], "rb") as der:
            private_bytes = der.read()
        private_pass = conf.CHANNEL_OPTION[self.__channel][PublicVerifier.PRIVATE_PASSWORD]

        if isinstance(private_pass, str):
            private_pass = private_pass.encode()
        try:
            try:
                temp_private = serialization\
                    .load_der_private_key(private_bytes,
                                          private_pass,
                                          default_backend())
            except Exception as e:
                # try pem type private load
                temp_private = serialization \
                    .load_pem_private_key(private_bytes,
                                          private_pass,
                                          default_backend())
        except Exception as e:
            raise ValueError("Invalid Password(Peer Certificate load test)")

        no_pass_private = temp_private.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        key_info = keys.PrivateKeyInfo.load(no_pass_private)

        self.__peer_pri = PrivateKey(long_to_bytes(key_info['private_key'].native['private_key']))
        self._init_using_pub(self.__peer_pri.pubkey.serialize(compressed=False))

        # 키 쌍 검증
        sign = self.sign_data(b'TEST')
        if self.verify_data(b'TEST', sign) is False:
            raise ValueError("Invalid Signature(Peer Certificate load test)")

    @property
    def peer_private_key(self):
        return self.__peer_pri

    def sign_data(self, data, is_hash=False):
        if is_hash:
            if isinstance(data, str):
                try:
                    data = binascii.unhexlify(util.trim_hex(data))
                except Exception as e:
                    logging.error(f"hash data must hex string or bytes \n exception : {e}")
                    return None

        if not isinstance(data, (bytes, bytearray)):
            logging.error(f"data must be bytes \n")
            return None

        signature = self.__peer_pri.ecdsa_sign_recoverable(msg=data,
                                                           raw=is_hash,
                                                           digest=hashlib.sha3_256)
        serialized_sig = self._pri.ecdsa_recoverable_serialize(signature)

        return b''.join([serialized_sig[0], bytes([serialized_sig[1]])])
