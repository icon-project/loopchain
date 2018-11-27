import hashlib

from abc import abstractmethod, ABC
from typing import TYPE_CHECKING
from .. import Signature, Address
from ..hashing import build_hash_generator

if TYPE_CHECKING:
    from secp256k1 import PrivateKey
    from . import Transaction
    from .. import Hash32


class TransactionBuilder(ABC):
    _hash_salt = None

    def __init__(self, hash_generator_version: int):
        self._hash_generator = build_hash_generator(hash_generator_version, self._hash_salt)

        # Attributes that must be assigned
        self.private_key: 'PrivateKey' = None

        # Attributes to be generated
        self.from_address: 'Address' = None
        self.hash: 'Hash32' = None
        self.signature: 'Signature' = None

    def reset_cache(self):
        self.from_address = None
        self.hash = None
        self.signature = None

    @abstractmethod
    def build(self) -> 'Transaction':
        raise NotImplementedError

    def build_hash(self):
        if self.from_address is None:
            raise RuntimeError

        self.hash = self._build_hash()
        return self.hash

    @abstractmethod
    def _build_hash(self) -> 'Hash32':
        raise NotImplementedError

    def build_from_address(self):
        if self.private_key is None:
            raise RuntimeError

        self.from_address = self._build_from_address()
        return self.from_address

    def _build_from_address(self):
        serialized_pub = self.private_key.pubkey.serialize(compressed=False)
        hashed_pub = hashlib.sha3_256(serialized_pub[1:]).digest()
        return Address(hashed_pub[-20:])

    def sign(self):
        if self.hash is None:
            self.build_hash()

        self.signature = self._sign()
        return self.signature

    def _sign(self):
        raw_sig = self.private_key.ecdsa_sign_recoverable(msg=self.hash,
                                                          raw=True,
                                                          digest=hashlib.sha3_256)
        serialized_sig, recover_id = self.private_key.ecdsa_recoverable_serialize(raw_sig)
        signature = serialized_sig + bytes((recover_id, ))
        return Signature(signature)

    @classmethod
    def new(cls, version: str, hash_generator_version: int):
        from . import genesis, v2, v3
        if version == genesis.version:
            return genesis.TransactionBuilder(hash_generator_version)
        elif version == v2.version:
            return v2.TransactionBuilder(hash_generator_version)
        elif version == v3.version:
            return v3.TransactionBuilder(hash_generator_version)

        raise RuntimeError
