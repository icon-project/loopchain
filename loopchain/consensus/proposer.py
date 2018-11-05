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
"""A Proposer module for block """

import sys
import logging
import pickle

from loopchain import configure as conf
from loopchain.blockchain import *
from loopchain.baseservice import ObjectManager
from loopchain.consensus import Subscriber, Epoch, Consensus
from loopchain.baseservice.aging_cache import AgingCache


# Changing the import location will cause a pickle error.
import loopchain_pb2

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from loopchain.channel.channel_service import ChannelService


class Proposer(Subscriber):
    def __init__(self, name: str, channel: str, peer_id: str, channel_service: 'ChannelService', **kwargs):
        Subscriber.__init__(self, name)
        self.__channel = channel
        self.__channel_service: 'ChannelService' = channel_service
        self.__block_manager: 'BlockManager' = self.__channel_service.block_manager
        self.__peer_id = peer_id
        self.__prev_epoch: Epoch = kwargs.get("prev_epoch", None)
        self.__precommit_block: Block = kwargs.get("precommit_block", None)
        self.__epoch = kwargs.get("epoch", None)
        self._event_list = [
            (Consensus.EVENT_COMPLETE_CONSENSUS, self.callback_complete_consensus),
            (Consensus.EVENT_MAKE_BLOCK, self.callback_make_block)
        ]
        self.__block: Block = None
        self.__block_tx_size = 0
        self.__current_vote_block_hash = ""

    @property
    def peer_id(self, peer_id):
        self.__peer_id = peer_id

    def __init_block(self):
        self.__block = Block(channel_name=self.__channel, made_block_count=1)
        self.__block_tx_size = 0

    def __makeup_block(self, tx_queue: AgingCache):
        """Queue 에 수집된 tx 를 block 으로 만든다.
        setttings 에 정의된 조건에 따라 한번의 작업으로 여러개의 candidate_block 으로 나뉘어진 블럭을 생성할 수 있다.
        (주의! 성능상의 이유로 가능한 운행 조건에서 블럭이 나누어지지 않도록 설정하는 것이 좋다.)
        """
        while tx_queue:
            if self.__block_tx_size >= conf.MAX_TX_SIZE_IN_BLOCK:
                logging.debug(f"Proposer:: total size({self.__block_tx_size}) "
                              f"count({len(self.__block.confirmed_transaction_list)}) "
                              f"_txQueue size ({len(tx_queue)})")
                break

            # 수집된 tx 가 있으면 Block 에 집어 넣는다.
            tx = tx_queue.get_item_in_status(
                TransactionStatusInQueue.normal,
                TransactionStatusInQueue.added_to_block)

            if tx is None:
                break

            if isinstance(tx, Transaction):
                # Check tx_hash is unique!
                if self.__block_manager.get_tx(tx.tx_hash) is None:
                    # util.logger.spam(f"Proposer:__make_block:: txQueue get tx: {tx.tx_hash}")
                    if self.__block.put_transaction(tx):
                        self.__block_tx_size += sys.getsizeof(pickle.dumps(tx))
                else:
                    logging.warning(f"tx hash conflict ({tx.tx_hash})")
            else:
                logging.error("Load Transaction Error!")
                continue

            if self.__block is None:
                logging.error("Proposer Leader Can't Add tx...")

        consensus = self.__channel_service.consensus
        self.__block.peer_id = consensus.leader_id
        self.__block.generate_block(self.__precommit_block)

    def __create_block(self, tx_queue: AgingCache):
        logging.debug(f"proposer.py:__create_block::CREATE BLOCK !!")
        self.__generate_block(tx_queue)

        block_is_verified = True
        if conf.CHANNEL_OPTION[self.__channel]['store_valid_transaction_only']:
            block_is_verified, need_rebuild, invoke_results = self.__block.verify_through_score_invoke(is_leader=True)

            old_block_hash = self.__block.block_hash

            if need_rebuild:
                verified_commit_state = copy.deepcopy(self.__block.commit_state)
                self.__block.generate_block(self.__precommit_block)
                assert verified_commit_state == self.__block.commit_state

                ObjectManager().peer_service.score_change_block_hash(channel=self._channel_name,
                                                                     block_height=self._block.height,
                                                                     old_block_hash=old_block_hash,
                                                                     new_block_hash=self._block.block_hash)

            self.__block_manager.set_invoke_results(self.__block.block_hash, invoke_results)
            self.__block_manager.set_last_commit_state(self.__block.height, self.__block.commit_state)

        if block_is_verified:
            self.__block.sign(self.__channel_service.peer_auth)
        else:
            self.__throw_out_block(self.__block)

        self.__epoch.block_hash = self.__block.block_hash
        self.__broadcast_block()

    def __throw_out_block(self, target_block):
        logging.debug(f"Throw out Block!!! {target_block.height}, {target_block.block_hash} ")
        self.__block.prev_block_confirm = False
        self.__block.prev_block_hash = target_block.prev_block_hash
        self.__block.height = target_block.height
        self.__block.time_stamp = 0
        self.__block_tx_size = 0

        self.__current_vote_block_hash = ""

    def __broadcast_block(self):
        """생성된 block 을 피어들에게 broadcast 하여 검증을 요청한다.
        """
        logging.debug(f"Proposer::__broadcast_block: {self.__block.height}, {self.__block.block_hash}")
        logging.debug(f"BroadCast AnnounceNewBlockForVote...peers: "
                      f"{self.__channel_service.peer_manager.get_peer_count()}")

        self.__block_manager.get_blockchain().increase_made_block_count()
        self.__channel_service.broadcast_scheduler.schedule_broadcast(
            "AnnounceNewBlockForVote",
            (loopchain_pb2.NewBlockSend(
                block=pickle.dumps(self.__block),
                epoch=pickle.dumps(self.__epoch),
                channel=self.__channel)))

        self.__channel_service.acceptor.create_vote(block=self.__block, epoch=self.__epoch)

    def __generate_block(self, tx_queue: AgingCache):
        util.logger.spam(f"proposer.py:__generate_block::GENERATE BLOCK")
        self.__init_block()
        self.__block.peer_id = self.__peer_id
        self.__block.block_status = BlockStatus.confirmed
        self.__makeup_block(tx_queue)

    def callback_complete_consensus(self, **kwargs):
        self.__prev_epoch = kwargs.get("prev_epoch", None)
        self.__precommit_block = kwargs.get("precommit_block", None)
        self.__epoch = kwargs.get("epoch", None)
        self.__block = None
        util.logger.spam(f"Proposer:callback_complete_consensus::epoch height"
                         f"{self.__epoch if not self.__epoch else self.__epoch.block_height}/precommit_block height"
                         f"{None if not self.__precommit_block else self.__precommit_block.height}")

    def callback_make_block(self, **kwargs):
        tx_queue = kwargs.get("tx_queue")
        consensus = self.__channel_service.consensus
        current_leader_id = consensus.leader_id
        tx = tx_queue.get_item_in_status(TransactionStatusInQueue.normal, TransactionStatusInQueue.normal)

        if self.__peer_id != current_leader_id:
            # util.logger.spam(f"proposer:callback_make_block::ummmmmm "
            #                  f"It's not leader peer.({self.__peer_id}/{current_leader_id})")
            return

        if self.__block and self.__epoch.block_height == self.__block.height:
            util.logger.spam(f"It needs to be increased epoch. "
                             f"epoch_height:{self.__epoch.block_height}/block_height:{self.__block.height}")
            return

        if not conf.ALLOW_MAKE_EMPTY_BLOCK:
            if tx is None or consensus.epoch.precommit_block.height != self.__precommit_block.height:
                util.logger.spam(f"tx is None or not same block height "
                                 f"{consensus.epoch.precommit_block.height}/{self.__precommit_block.height}")
                return

        util.logger.spam(f"current_leader_id({current_leader_id})/tx({tx})")
        logging.debug(
            f"hrkim >>> proposer :: It's leader and has tx ! let's create block {self.__precommit_block.height+1}!")
        self.__create_block(tx_queue)
        util.logger.spam(f"Proposer::callback_make_block:: peer_id({self.__peer_id})"
                         f"current_leader_id({current_leader_id})tx({tx}/"
                         f"{None if not tx else tx_queue.get_item_status(tx.tx_hash)})")

        return True
