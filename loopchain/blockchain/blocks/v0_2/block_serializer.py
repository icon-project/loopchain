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
        block_serialized["complained"] = 1 if header.is_complained else 0
        return block_serialized

    def _deserialize_header_data(self, json_data: dict):
        header = super()._deserialize_header_data(json_data)
        if json_data["complained"] == 1:
            header["complained"] = True
        elif json_data["complained"] == 0:
            header["complained"] = False
        else:
            raise RuntimeError(f'Block({json_data} malformed. complained: {json_data["complained"]}')
        return header
