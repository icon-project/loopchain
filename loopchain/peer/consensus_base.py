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
import logging
import traceback
from abc import ABCMeta, abstractmethod

import loopchain.utils as util
from loopchain import configure as conf
from loopchain.blockchain import BlockBuilder
from loopchain.blockchain import Transaction, TransactionStatusInQueue, TransactionVerifier


class ConsensusBase(metaclass=ABCMeta):
    """LoopChain 의 Consensus Algorithm 을 표현하는 클래스
    """

    def __init__(self, blockmanager):
        self._blockmanager = blockmanager
        self._channel_name = blockmanager.channel_name
        self._made_block_count = 0
        self._blockchain = self._blockmanager.get_blockchain()
        self._txQueue = self._blockmanager.get_tx_queue()

    @property
    def made_block_count(self):
        return self._made_block_count

    def stop(self):
        pass

    @abstractmethod
    async def consensus(self):
        """Block Manager 의 Thread Loop 에서 호출 하는 합의 알고리즘
        """
        pass

    def _check_unconfirmed_block(self):
        util.logger.notice(f"-------------------_check_unconfirmed_block, "
                           f"candidate_blocks({len(self._blockmanager.candidate_blocks.blocks)})")
        if self._blockchain.last_unconfirmed_block:
            vote = self._blockmanager.candidate_blocks.get_vote(self._blockchain.last_unconfirmed_block.header.hash)
            util.logger.notice(f"-------------------_check_unconfirmed_block, "
                               f"last_unconfirmed_block({self._blockchain.last_unconfirmed_block.header.hash}), "
                               f"vote({vote.votes})")
            vote_result = vote.get_result(self._blockchain.last_unconfirmed_block.header.hash.hex(), conf.VOTING_RATIO)
            if not vote_result:
                util.logger.notice(f"-------------------_check_unconfirmed_block, "
                                   f"last_unconfirmed_block({self._blockchain.last_unconfirmed_block.header.hash}), "
                                   f"vote result({vote_result})")

    def _makeup_block(self):
        self._check_unconfirmed_block()
        block_height = self._blockchain.last_block.header.height + 1
        block_version = self._blockchain.block_versioner.get_version(block_height)
        block_builder = BlockBuilder.new(block_version, self._blockchain.tx_versioner)

        tx_versioner = self._blockchain.tx_versioner
        while self._txQueue:
            if block_builder.size() >= conf.MAX_TX_SIZE_IN_BLOCK:
                logging.debug(f"consensus_base total size({block_builder.size()}) "
                              f"count({len(block_builder.transactions)}) "
                              f"_txQueue size ({len(self._txQueue)})")
                break

            tx: 'Transaction' = self._txQueue.get_item_in_status(
                TransactionStatusInQueue.normal,
                TransactionStatusInQueue.added_to_block
            )
            if tx is None:
                break

            tv = TransactionVerifier.new(tx.version, tx_versioner)

            try:
                tv.verify(tx, self._blockchain)
            except Exception as e:
                logging.warning(f"tx hash invalid.\n"
                                f"tx: {tx}\n"
                                f"exception: {e}")
                traceback.print_exc()
            else:
                block_builder.transactions[tx.hash] = tx

        return block_builder
