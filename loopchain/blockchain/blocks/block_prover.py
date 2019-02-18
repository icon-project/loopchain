from abc import ABC, abstractmethod
from typing import List, Union, Iterable
from .. import Hash32


class BlockProver(ABC):
    def __init__(self, hashes: Union[Iterable[Hash32], List[Hash32]]):
        self.hashes = hashes

    @abstractmethod
    def get_proof(self, hash_or_index: Hash32) -> list:
        raise NotImplementedError

    @abstractmethod
    def get_proof_root(self) -> Hash32:
        raise NotImplementedError

    @abstractmethod
    def prove(self, hash_: Hash32, root_hash: Hash32, proof: list) -> bool:
        raise NotImplementedError

    @classmethod
    def new(cls, version: str, hashes: List[Hash32]):
        from . import v0_3
        if version == v0_3.version:
            return v0_3.BlockProver(hashes)

        from . import v0_1a
        if version == v0_1a.version:
            return v0_1a.BlockProver(hashes)

        raise NotImplementedError(f"BlockBuilder Version({version}) not supported.")
