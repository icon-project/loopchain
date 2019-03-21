import hashlib

from abc import abstractmethod, ABC
from typing import TYPE_CHECKING
from loopchain.crypto.hashing import build_hash_generator

from .. import Signature, ExternalAddress, Hash32

if TYPE_CHECKING:
    from secp256k1 import PrivateKey
    from . import Transaction, TransactionVersioner


class TransactionBuilder(ABC):
    _hash_salt = None

    def __init__(self, hash_generator_version: int):
        self._hash_generator = build_hash_generator(hash_generator_version, self._hash_salt)

        # Attributes that must be assigned
        self.private_key: 'PrivateKey' = None

        # Attributes to be generated
        self.from_address: 'ExternalAddress' = None
        self.hash: 'Hash32' = None
        self.signature: 'Signature' = None
        self.origin_data: dict = None
        self.raw_data: dict = None

    def reset_cache(self):
        self.from_address = None
        self.hash = None
        self.signature = None
        self.origin_data = None
        self.raw_data = None

    @abstractmethod
    def build(self) -> 'Transaction':
        raise NotImplementedError

    def build_hash(self):
        if self.origin_data is None:
            raise RuntimeError(f"origin data is required. Run build_origin_data.")

        self.hash = self._build_hash()
        return self.hash

    def _build_hash(self):
        return Hash32(self._hash_generator.generate_hash(self.origin_data))

    def build_from_address(self):
        if self.private_key is None:
            raise RuntimeError(f"private_key is required.")

        self.from_address = self._build_from_address()
        return self.from_address

    def _build_from_address(self):
        serialized_pub = self.private_key.pubkey.serialize(compressed=False)
        hashed_pub = hashlib.sha3_256(serialized_pub[1:]).digest()
        return ExternalAddress(hashed_pub[-20:])

    @abstractmethod
    def build_raw_data(self) -> dict:
        pass

    @abstractmethod
    def build_origin_data(self) -> dict:
        pass

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
    def new(cls, version: str, versioner: 'TransactionVersioner'):
        hash_generator_version = versioner.get_hash_generator_version(version)

        from . import v3
        if version == v3.version:
            return v3.TransactionBuilder(hash_generator_version)

        from . import v2
        if version == v2.version:
            return v2.TransactionBuilder(hash_generator_version)

        from . import genesis
        if version == genesis.version:
            return genesis.TransactionBuilder(hash_generator_version)

        raise RuntimeError(f"Not supported tx version({version})")
