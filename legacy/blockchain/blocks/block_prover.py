from abc import ABC, abstractmethod
from enum import Enum, auto
from typing import Union, Iterable, Optional

from legacy.blockchain.types import Hash32


class BlockProver(ABC):
    def __init__(self, values: Iterable, type_: 'BlockProverType'):
        self.hashes = values
        self.type = type_

    @abstractmethod
    def get_proof(self, hash_or_index: Union[Hash32, int]) -> list:
        raise NotImplementedError

    @abstractmethod
    def get_proof_root(self) -> Hash32:
        raise NotImplementedError

    @abstractmethod
    def prove(self, hash_: Hash32, root_hash: Hash32, proof: list) -> bool:
        raise NotImplementedError

    @abstractmethod
    def get_hash_generator(self):
        raise NotImplementedError

    @abstractmethod
    def to_hash32(self, value: Union[Hash32, bytes, bytearray, int, bool, dict]):
        raise NotImplementedError

    @classmethod
    def new(cls, version: str, values: Optional[Iterable], type_: 'BlockProverType'):
        from . import v0_5
        if version == v0_5.version:
            return v0_5.BlockProver(values, type_)

        from . import v0_4
        if version == v0_4.version:
            return v0_4.BlockProver(values, type_)

        from . import v0_3
        if version == v0_3.version:
            return v0_3.BlockProver(values, type_)

        from . import v0_1a
        if version == v0_1a.version:
            return v0_1a.BlockProver(values, type_)

        raise NotImplementedError(f"BlockBuilder Version({version}) not supported.")


class BlockProverType(Enum):
    Block = auto()
    Transaction = auto()
    Receipt = auto()
    Rep = auto()
    Vote = auto()
