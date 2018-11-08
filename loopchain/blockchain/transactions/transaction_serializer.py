from abc import abstractmethod, ABC
from typing import TYPE_CHECKING
from ..hashing import build_hash_generator

if TYPE_CHECKING:
    from .transaction import Transaction


class TransactionSerializer(ABC):
    _hash_salt = None

    def __init__(self, hash_generator_version: int):
        self._hash_generator = build_hash_generator(hash_generator_version, self._hash_salt)

    @abstractmethod
    def extract(self, tx: 'Transaction'):
        raise NotImplementedError

    @abstractmethod
    def serialize(self, tx: 'Transaction'):
        raise NotImplementedError

    @abstractmethod
    def deserialize(self, tx_dumped) -> 'Transaction':
        raise NotImplementedError

    @classmethod
    def new(cls, version: str, hash_generator_version: int):
        from . import genesis, v2, v3
        if version == genesis.version:
            return genesis.TransactionSerializer(hash_generator_version)
        elif version == v2.version:
            return v2.TransactionSerializer(hash_generator_version)
        elif version == v3.version:
            return v3.TransactionSerializer(hash_generator_version)

        raise RuntimeError
