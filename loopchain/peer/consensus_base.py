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
        self._block = None
        self._block_tx_size = 0
        self._blockmanager = blockmanager
        self._channel_name = blockmanager.channel_name
        self._blockchain = self._blockmanager.get_blockchain()
        self._txQueue = self._blockmanager.get_tx_queue()
        self._current_vote_block_hash = ""
        self._candidate_blocks = self._blockmanager.get_candidate_blocks()
        self._gen_block()

    @abstractmethod
    def consensus(self):
        """Block Manager 의 Thread Loop 에서 호출 하는 합의 알고리즘
        """
        pass

    @property
    def block(self):
        return self._block

    def _gen_block(self):
        self._reset_block()

    def _reset_block(self):
        self._block = Block(channel_name=self._channel_name)
        self._block_tx_size = 0

    def _stop_gen_block(self):
        self._block = None
        self._block_tx_size = 0

    def _makeup_block(self):
        """Queue 에 수집된 tx 를 block 으로 만든다.
        setttings 에 정의된 조건에 따라 한번의 작업으로 여러개의 candidate_block 으로 나뉘어진 블럭을 생성할 수 있다.
        (주의! 성능상의 이유로 가능한 운행 조건에서 블럭이 나누어지지 않도록 설정하는 것이 좋다.)
        """

        peer_manager_block = None
        while self._txQueue:
            if self._block_tx_size >= conf.MAX_TX_SIZE_IN_BLOCK:
                logging.debug(f"consensus_base total size({self._block_tx_size}) "
                              f"count({len(self._block.confirmed_transaction_list)}) "
                              f"_txQueue size ({len(self._txQueue)})")
                break

            # 수집된 tx 가 있으면 Block 에 집어 넣는다.
            tx = self._txQueue.get_item_in_status(
                TransactionStatusInQueue.normal,
                TransactionStatusInQueue.added_to_block
            )
            if tx is None:
                break

            if isinstance(tx, Transaction):
                # Check tx_hash is unique!
                if self._blockmanager.get_tx(tx.tx_hash) is None:
                    # logging.debug("consensus_base txQueue get tx: " + tx.tx_hash)
                    if self._block.put_transaction(tx):
                        self._block_tx_size += sys.getsizeof(pickle.dumps(tx))
                else:
                    logging.warning(f"tx hash conflict ({tx.tx_hash})")
            else:
                logging.error("Load Transaction Error!")
                continue

            if tx.type is TransactionType.peer_list:
                logging.debug("consensus_base Get tx type : peer_list")
                peer_manager_block = Block(channel_name=self._channel_name)
                peer_manager_block.block_type = BlockType.peer_list
                peer_manager_block.peer_manager = tx.get_data()
                break
            elif self._block is None:
                logging.error("consensus_base Leader Can't Add tx...")

        if peer_manager_block is not None:
            logging.debug("consensus_base:_makeup_block make peer_list block and sign it.")
            peer_manager_block.generate_block(self._candidate_blocks.get_last_block(self._blockchain))
            peer_manager_block.sign(
                ObjectManager().channel_service.peer_auth
            )
