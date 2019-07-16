from abc import abstractmethod, ABC
from typing import TYPE_CHECKING
from loopchain.crypto.hashing import build_hash_generator

if TYPE_CHECKING:
    from loopchain.blockchain.transactions import Transaction, TransactionVersioner


class TransactionSerializer(ABC):
    _hash_salt = None

    def __init__(self, hash_generator_version: int):
        self._hash_generator = build_hash_generator(hash_generator_version, self._hash_salt)

    @abstractmethod
    def to_origin_data(self, tx: 'Transaction'):
        raise NotImplementedError

    @abstractmethod
    def to_raw_data(self, tx: 'Transaction'):
        raise NotImplementedError

    @abstractmethod
    def to_full_data(self, tx: 'Transaction'):
        raise NotImplementedError

    @abstractmethod
    def to_db_data(self, tx: 'Transaction'):
        raise NotImplementedError

    @abstractmethod
    def from_(self, tx_dumped: dict) -> 'Transaction':
        raise NotImplementedError

    @abstractmethod
    def get_hash(self, tx_dumped: dict) -> str:
        raise NotImplementedError

    @classmethod
    def new(cls, version: str, type_: str, versioner: 'TransactionVersioner'):
        hash_generator_version = versioner.get_hash_generator_version(version)

        from . import v3_issue
        if version == v3_issue.version and type_ == "issue":
            return v3_issue.TransactionSerializer(hash_generator_version)

        from . import v3
        if version == v3.version:
            return v3.TransactionSerializer(hash_generator_version)

        from . import v2
        if version == v2.version:
            return v2.TransactionSerializer(hash_generator_version)

        from . import genesis
        if version == genesis.version:
            return genesis.TransactionSerializer(hash_generator_version)

        raise RuntimeError(f"Not supported tx version({version})")
