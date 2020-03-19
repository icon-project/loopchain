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
"""block builder for version 0.5 block"""

from legacy.blockchain.blocks import BlockProverType
from legacy.blockchain.blocks.v0_4 import BlockBuilder
from legacy.blockchain.blocks.v0_5 import BlockHeader, BlockBody, BlockProver
from legacy.blockchain.types import Hash32


class BlockBuilder(BlockBuilder):
    version = BlockHeader.version
    BlockHeaderClass = BlockHeader
    BlockBodyClass = BlockBody

    def _build_transactions_hash(self):
        if not self.transactions:
            return Hash32.empty()

        block_prover = BlockProver(self.transactions.keys(), BlockProverType.Transaction)
        return block_prover.get_proof_root()
