from typing import TYPE_CHECKING
from . import BlockHeader
from .. import v0_1a

if TYPE_CHECKING:
    from .. import Block


class BlockVerifier(v0_1a.BlockVerifier):
    version = BlockHeader.version

    def verify_prev_block(self, block: 'Block', prev_block: 'Block'):
        super().verify_prev_block(block, prev_block)

        prev_block_header: BlockHeader = prev_block.header
        block_header: BlockHeader = block.header

        # 임시로 주석 처리함 merge 전에 반드시 복원할 것!!!
        # if prev_block_header.next_leader and \
        #    prev_block_header.next_leader != block_header.peer_id:
        #         raise RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()}, "
        #                            f"Leader({block_header.peer_id.hex_xx()}), "
        #                            f"Expected({prev_block_header.next_leader.hex_xx()}).")
