from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from loopchain.blockchain.blocks import Block
from loopchain.blockchain.exception import BlockVersionNotMatch

if TYPE_CHECKING:
    from loopchain.blockchain.transactions import TransactionVersioner


class BlockSerializer(ABC):
    version = None
    BlockHeaderClass = None
    BlockBodyClass = None

    def __init__(self, tx_versioner: 'TransactionVersioner'):
        self._tx_versioner = tx_versioner

    def serialize(self, block: 'Block') -> dict:
        if block.header.version != self.version:
            raise BlockVersionNotMatch(block.header.version, self.version,
                                       "The block of this version cannot be serialized by the serializer.")
        return self._serialize(block)

    @abstractmethod
    def _serialize(self, block: 'Block') -> dict:
        raise NotImplementedError

    def deserialize(self, block_dumped: dict) -> 'Block':
        if block_dumped['version'] != self.version:
            raise BlockVersionNotMatch(block_dumped['version'], self.version,
                                       "The block of this version cannot be deserialized by the serializer.")
        return self._deserialize(block_dumped)

    def _deserialize(self, json_data):
        header_data = self._deserialize_header_data(json_data)
        header = self.BlockHeaderClass(**header_data)

        body_data = self._deserialize_body_data(json_data)
        body = self.BlockBodyClass(**body_data)
        return Block(header, body)

    @abstractmethod
    def _deserialize_header_data(self, json_data: dict):
        raise NotImplementedError

    @abstractmethod
    def _deserialize_body_data(self, json_data: dict):
        raise NotImplementedError

    @classmethod
    def new(cls, version: str, tx_versioner: 'TransactionVersioner') -> 'BlockSerializer':
        from . import v1_0
        if version == v1_0.version:
            return v1_0.BlockSerializer(tx_versioner)

        from . import v0_5
        if version == v0_5.version:
            return v0_5.BlockSerializer(tx_versioner)

        from . import v0_4
        if version == v0_4.version:
            return v0_4.BlockSerializer(tx_versioner)

        from . import v0_3
        if version == v0_3.version:
            return v0_3.BlockSerializer(tx_versioner)

        from . import v0_1a
        if version == v0_1a.version:
            return v0_1a.BlockSerializer(tx_versioner)

        raise NotImplementedError(f"BlockBuilder Version({version}) not supported.")
