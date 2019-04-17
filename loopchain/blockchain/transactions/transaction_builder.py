from abc import abstractmethod, ABC
from abc import abstractmethod, ABC
from typing import TYPE_CHECKING

from loopchain.crypto.hashing import build_hash_generator
from loopchain.crypto.signature import SignatureType
from .. import Signature, Hash32

if TYPE_CHECKING:
    from secp256k1 import PrivateKey
    from . import Transaction, TransactionVersioner


class TransactionBuilder(ABC):
    _hash_salt = None

    def __init__(self, hash_generator_version: int, signer: 'RecoverableSigner'):
        self._hash_generator = build_hash_generator(hash_generator_version, self._hash_salt)

        # Attributes that must be assigned
        self.signer = signer
        self.private_key: 'PrivateKey' = None

        # Attributes to be generated
        self.from_address: 'Address' = signer.address
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

    @abstractmethod
    def build_raw_data(self) -> dict:
        pass

    @abstractmethod
    def build_origin_data(self) -> dict:
        pass

    def sign(self):
        if self.hash is None:
            self.build_hash()

        self.signature = self.signer.sign_hash(self.hash, SignatureType.NONE)
        return self.signature

    @classmethod
    def new(cls, version: str, versioner: 'TransactionVersioner', signer: 'RecoverableSigner'):
        hash_generator_version = versioner.get_hash_generator_version(version)

        from . import v3
        if version == v3.version:
            return v3.TransactionBuilder(hash_generator_version, signer)

        from . import v2
        if version == v2.version:
            return v2.TransactionBuilder(hash_generator_version, signer)

        from . import genesis
        if version == genesis.version:
            return genesis.TransactionBuilder(hash_generator_version, signer)

        raise RuntimeError(f"Not supported tx version({version})")
