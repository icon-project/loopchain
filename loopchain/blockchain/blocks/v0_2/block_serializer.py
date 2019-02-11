from . import BlockHeader, BlockBody
from .. import Block, v0_1a


class BlockSerializer(v0_1a.BlockSerializer):
    version = BlockHeader.version
    BlockHeaderClass = BlockHeader
    BlockBodyClass = BlockBody

    def _serialize(self, block: 'Block'):
        header: BlockHeader = block.header
        block_serialized = super()._serialize(block)
        block_serialized["next_leader"] = header.next_leader.hex_xx()
        block_serialized["complained"] = "0x1" if header.complained else "0x0"
        return block_serialized

    def _deserialize_header_data(self, json_data: dict):
        header = super()._deserialize_header_data(json_data)
        header["complained"] = True if json_data["complained"] == "0x1" else False
        return header
