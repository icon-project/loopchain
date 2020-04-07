from abc import abstractmethod, ABC
from typing import TYPE_CHECKING
from loopchain.crypto.hashing import build_hash_generator
from loopchain.blockchain.types import Signature, ExternalAddress, Hash32

if TYPE_CHECKING:
    from loopchain.crypto.signature import Signer
    from loopchain.blockchain.transactions import Transaction, TransactionVersioner


class TransactionBuilder(ABC):
    _hash_salt = None

    def __init__(self, hash_generator_version: int):
        self._hash_generator = build_hash_generator(hash_generator_version, self._hash_salt)

        # Attributes that must be assigned
        self.signer: 'Signer' = None

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
    def build(self, is_signing=True) -> 'Transaction':
        raise NotImplementedError

    def build_hash(self):
        if self.origin_data is None:
            raise RuntimeError(f"origin data is required. Run build_origin_data.")

        self.hash = self._build_hash()
        return self.hash

    def _build_hash(self):
        return Hash32(self._hash_generator.generate_hash(self.origin_data))

    def build_from_address(self):
        if self.from_address:
            return self.from_address

        if self.signer is None:
            raise RuntimeError(f"'signer' or 'from_address' is required.")

        self.from_address = ExternalAddress.fromhex_address(self.signer.address)
        return self.from_address

    @abstractmethod
    def build_raw_data(self, is_signing=True) -> dict:
        pass

    @abstractmethod
    def build_origin_data(self) -> dict:
        pass

    def sign(self):
        if self.hash is None:
            self.build_hash()

        self.signature = Signature(self.signer.sign_hash(self.hash))
        return self.signature

    @abstractmethod
    def sign_transaction(self, tx: 'Transaction'):
        raise NotImplementedError

    @classmethod
    def new(cls, version: str, type_: str, versioner: 'TransactionVersioner'):
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
