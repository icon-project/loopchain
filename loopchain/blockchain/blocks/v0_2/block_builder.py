from . import BlockHeader, BlockBody
from .. import v0_1a, Block


class BlockBuilder(v0_1a.BlockBuilder):
    def _build(self):
        header = BlockHeader(
            hash=self.hash,
            prev_hash=self.prev_hash,
            height=self.height,
            timestamp=self._timestamp,
            peer_id=self.peer_id,
            signature=self.signature,
            next_leader=self.next_leader,
            merkle_tree_root_hash=self.merkle_tree_root_hash,
            commit_state=self.commit_state)
        body = BlockBody(self.transactions, self.confirm_prev_block)
        self.block = Block(header, body)
        return self.block
