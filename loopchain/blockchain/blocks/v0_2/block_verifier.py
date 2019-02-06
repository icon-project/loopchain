# Copyright 2018 ICON Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from typing import TYPE_CHECKING

from . import BlockHeader
from .. import v0_1a
from .... import utils as util

if TYPE_CHECKING:
    from .. import Block


class BlockVerifier(v0_1a.BlockVerifier):
    version = BlockHeader.version

    def verify_prev_block(self, block: 'Block', prev_block: 'Block'):
        super().verify_prev_block(block, prev_block)

        prev_block_header: BlockHeader = prev_block.header
        block_header: BlockHeader = block.header

        if not block_header.is_complain and prev_block_header.next_leader and \
           prev_block_header.next_leader != block_header.peer_id:
                raise RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()}, "
                                   f"Leader({block_header.peer_id.hex_xx()}), "
                                   f"Expected({prev_block_header.next_leader.hex_xx()}).")

    def verify_generator(self, block: 'Block', generator: 'ExternalAddress'):
        util.logger.notice(f"block v0.2 verify_generator")
        if not block.header.is_complain and block.header.peer_id != generator:
            raise RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()}, "
                               f"Generator({block.header.peer_id.hex_xx()}), "
                               f"Expected({generator.hex_xx()}).")
