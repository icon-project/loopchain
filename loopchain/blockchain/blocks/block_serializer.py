from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..blocks import Block


class BlockSerializer(ABC):
    @abstractmethod
    def serialize(self, block: 'Block') -> dict:
        raise NotImplementedError

    @abstractmethod
    def deserialize(self, block_dumped: dict) -> 'Block':
        raise NotImplementedError

    @classmethod
    def new(cls, version: str) -> 'BlockSerializer':
        from . import v0_1a
        if version == v0_1a.version:
            return v0_1a.BlockSerializer()

        raise RuntimeError
