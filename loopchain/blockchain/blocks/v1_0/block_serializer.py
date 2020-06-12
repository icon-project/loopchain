# Copyright 2018-current ICON Foundation
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
"""block serializer for version 0.5 block"""

from typing import TYPE_CHECKING

from loopchain.blockchain.blocks.block_serializer import BlockSerializer as BaseBlockSerializer
from loopchain.blockchain.blocks.v1_0 import Block, BlockHeader, BlockBody

if TYPE_CHECKING:
    from lft.consensus.messages.data import Data


class BlockSerializer(BaseBlockSerializer):
    version = BlockHeader.version
    BlockHeaderClass = BlockHeader
    BlockBodyClass = BlockBody

    def _serialize(self, block: 'Data'):
        return block._serialize()

    def _deserialize(self, json_data: dict):
        return Block._deserialize(**json_data)

    def _deserialize_header_data(self, json_data: dict):
        pass

    def _deserialize_body_data(self, json_data: dict):
        pass

