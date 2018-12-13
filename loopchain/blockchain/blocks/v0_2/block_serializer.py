from . import BlockHeader, BlockBody
from .. import Block, v0_1a
from ... import BlockVersionNotMatch


class BlockSerializer(v0_1a.BlockSerializer):
    def serialize(self, block: 'Block'):
        if block.header.version != BlockHeader.version:
            raise BlockVersionNotMatch(block.header.version, BlockHeader.version,
                                       "The block of this version cannot be serialized by the serializer.")
        return self._serialize(block)

    def _serialize(self, block: 'Block'):
        header: BlockHeader = block.header

        block_serialized = super()._serialize(block)
        block_serialized["next_leader"] = header.next_leader.hex_xx()
        return block_serialized

    def deserialize(self, json_data):
        if json_data['version'] != BlockHeader.version:
            raise BlockVersionNotMatch(json_data['version'], BlockHeader.version,
                                       "The block of this version cannot be deserialized by the serializer.")

        return self._deserialize(*self._deserialize_data(json_data))

    def _deserialize(self, hash, prev_hash, height, timestamp, peer_id, signature, next_leader, commit_state,
                     merkle_tree_root_hash, confirm_prev_block, transactions):
        header = BlockHeader(
            hash=hash,
            prev_hash=prev_hash,
            height=height,
            timestamp=timestamp,
            peer_id=peer_id,
            signature=signature,
            next_leader=next_leader,
            merkle_tree_root_hash=merkle_tree_root_hash,
            commit_state=commit_state
        )

        body = BlockBody(transactions, confirm_prev_block)
        return Block(header, body)
