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
"""A base class of consensus for the loopchain"""
import sys

from loopchain.baseservice import ObjectManager
from loopchain.blockchain import *


class ConsensusBase(metaclass=ABCMeta):
    """LoopChain 의 Consensus Algorithm 을 표현하는 클래스
    """

    def __init__(self, blockmanager):
        self._blockmanager = blockmanager
        self._channel_name = blockmanager.channel_name
        self._blockchain = self._blockmanager.get_blockchain()
        self._txQueue = self._blockmanager.get_tx_queue()

    def stop(self):
        pass

    @abstractmethod
    def consensus(self):
        """Block Manager 의 Thread Loop 에서 호출 하는 합의 알고리즘
        """
        pass

    def _makeup_block(self):
        block_builder = BlockBuilder.new("0.1a")

        tx_versions = TransactionVersions()
        while self._txQueue:
            if len(block_builder) >= conf.MAX_TX_SIZE_IN_BLOCK:
                logging.debug(f"consensus_base total size({len(block_builder)}) "
                              f"count({len(block_builder.transactions)}) "
                              f"_txQueue size ({len(self._txQueue)})")
                break

            tx: 'Transaction' = self._txQueue.get_item_in_status(
                TransactionStatusInQueue.normal,
                TransactionStatusInQueue.added_to_block
            )
            if tx is None:
                break

            tx_hash_version = tx_versions.get_hash_generator_version(tx.version)
            tv = TransactionVerifier.new(tx.version, tx_hash_version)

            try:
                tv.verify(tx, self._blockchain)
            except Exception as e:
                logging.warning(f"tx hash invalid. tx: {tx}")

            block_builder.transactions[tx.hash] = tx

        return block_builder
