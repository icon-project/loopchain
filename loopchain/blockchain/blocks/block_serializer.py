from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .. import TransactionVersioner
    from ..blocks import Block


class BlockSerializer(ABC):
    def __init__(self, tx_versioner: 'TransactionVersioner'):
        self._tx_versioner = tx_versioner

    @abstractmethod
    def serialize(self, block: 'Block') -> dict:
        raise NotImplementedError

    @abstractmethod
    def deserialize(self, block_dumped: dict) -> 'Block':
        raise NotImplementedError

    @classmethod
    def new(cls, version: str, tx_versioner: 'TransactionVersioner') -> 'BlockSerializer':
        from . import v0_1a
        if version == v0_1a.version:
            return v0_1a.BlockSerializer(tx_versioner)

        raise RuntimeError
