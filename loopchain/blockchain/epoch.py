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
"""It manages the information needed during consensus to store one block height.
Candidate Blocks, Quorum, Votes and Leader Complaints.
"""

import logging
import traceback
from typing import Dict, Optional
from loopchain import utils, configure as conf
from loopchain.baseservice import ObjectManager
from loopchain.blockchain.votes.v0_1a import LeaderVotes, LeaderVote
from loopchain.blockchain.types import TransactionStatusInQueue, ExternalAddress
from loopchain.blockchain.blocks import BlockBuilder
from loopchain.blockchain.transactions import Transaction, TransactionVerifier
from loopchain.channel.channel_property import ChannelProperty


class Epoch:
    def __init__(self, block_manager, leader_id=None):
        self.__block_manager = block_manager
        self.__blockchain = block_manager.blockchain
        if self.__blockchain.last_block:
            self.height = self.__blockchain.last_block.header.height + 1
        else:
            self.height = 1
        self.leader_id = leader_id
        utils.logger.debug(f"New Epoch Start height({self.height }) leader_id({leader_id})")

        # TODO using Epoch in BlockManager instead using candidate_blocks directly.
        # But now! only collect leader complain votes.
        self.__candidate_blocks = None

        self.round = 0
        self.complain_votes: Dict[int, LeaderVotes] = {}
        self.complained_result = None
        self.reps = []  # init by self.new_votes()

        self.new_votes()
        self.new_round(leader_id, self.__blockchain.peer_id, 0)

    @property
    def complain_duration(self):
        return min((2 ** self.round) * conf.TIMEOUT_FOR_LEADER_COMPLAIN, conf.MAX_TIMEOUT_FOR_LEADER_COMPLAIN)

    @staticmethod
    def new_epoch(leader_id=None):
        block_manager = ObjectManager().channel_service.block_manager
        leader_id = leader_id or ObjectManager().channel_service.block_manager.epoch.leader_id
        return Epoch(block_manager, leader_id)

    def new_round(self, new_leader_id, peer_id, round_=None):
        is_complained = round_ != 0
        self.set_epoch_leader(new_leader_id, peer_id, is_complained)

        if round_ is None:
            self.round += 1
        else:
            self.round = round_

        logging.debug(f"new round {round_}, {self.round}")

        self.new_votes()

    def new_votes(self):
        audience = ObjectManager().channel_service.peer_manager.peer_list
        rep_info = sorted(audience.values(), key=lambda peer: peer.order)
        self.reps = [ExternalAddress.fromhex(rep.peer_id) for rep in rep_info]

        leader_votes = LeaderVotes(self.reps,
                                   conf.LEADER_COMPLAIN_RATIO,
                                   self.height,
                                   ExternalAddress.fromhex_address(self.leader_id))
        self.complain_votes[self.round] = leader_votes

    def set_epoch_leader(self, leader_id, peer_id, complained=False):
        utils.logger.debug(f"Set Epoch leader height({self.height}) leader_id({leader_id})")
        self.leader_id = leader_id
        if complained and leader_id == peer_id:
            self.complained_result = complained
        else:
            self.complained_result = None

    def add_complain(self, leader_vote: LeaderVote):
        utils.logger.debug(f"add_complain complain_leader_id({leader_vote.old_leader}), "
                           f"new_leader_id({leader_vote.new_leader}), "
                           f"block_height({leader_vote.block_height}), "
                           f"peer_id({leader_vote.rep})")
        try:
            self.complain_votes[self.round].add_vote(leader_vote)
        except RuntimeError as e:
            logging.warning(e)

    def complain_result(self) -> Optional[str]:
        """return new leader id when complete complain leader.

        :return: new leader id or None
        """
        utils.logger.debug(f"complain_result vote_result({self.complain_votes[self.round].get_summary()})")
        if self.complain_votes[self.round].is_completed():
            vote_result = self.complain_votes[self.round].get_result()
            return vote_result.hex_hx()
        else:
            return None

    def _check_unconfirmed_block(self):
        if self.__blockchain.last_unconfirmed_block:
            vote = self.__block_manager.candidate_blocks.get_votes(
                self.__blockchain.last_unconfirmed_block.header.hash)
            vote_result = vote.get_result(
                self.__blockchain.last_unconfirmed_block.header.hash.hex(), conf.VOTING_RATIO)

            if not vote_result:
                utils.logger.debug(
                    f"last_unconfirmed_block"
                    f"({self.__blockchain.last_unconfirmed_block.header.hash}), "
                    f"vote result({vote_result})")

    def __add_tx_to_block(self, block_builder):
        tx_queue = self.__block_manager.get_tx_queue()

        block_tx_size = 0
        tx_versioner = self.__blockchain.tx_versioner
        while tx_queue:
            if block_tx_size >= conf.MAX_TX_SIZE_IN_BLOCK:
                logging.debug(f"consensus_base total size({block_builder.size()}) "
                              f"count({len(block_builder.transactions)}) "
                              f"_txQueue size ({len(tx_queue)})")
                break

            tx: 'Transaction' = tx_queue.get_item_in_status(
                TransactionStatusInQueue.normal,
                TransactionStatusInQueue.added_to_block
            )
            if tx is None:
                break

            if not utils.is_in_time_boundary(tx.timestamp, conf.TIMESTAMP_BOUNDARY_SECOND_IN_BLOCK):
                utils.logger.info(f"fail add tx to block by TIMESTAMP_BOUNDARY_SECOND_IN_BLOCK"
                                  f"({conf.TIMESTAMP_BOUNDARY_SECOND_IN_BLOCK}) "
                                  f"tx({tx.hash}), timestamp({tx.timestamp})")
                continue

            tv = TransactionVerifier.new(tx.version, tx.type(), tx_versioner)

            try:
                tv.verify(tx, self.__blockchain)
            except Exception as e:
                logging.warning(f"tx hash invalid.\n"
                                f"tx: {tx}\n"
                                f"exception: {e}")
                traceback.print_exc()
            else:
                block_builder.transactions[tx.hash] = tx
                block_tx_size += tx.size(tx_versioner)

    def remove_duplicate_tx_when_turn_to_leader(self):
        if self.__blockchain.last_unconfirmed_block and \
                self.__blockchain.last_unconfirmed_block.header.peer_id != ChannelProperty().peer_address:
            tx_queue = self.__block_manager.get_tx_queue()
            for tx_hash_in_unconfirmed_block in self.__blockchain.last_unconfirmed_block.body.transactions:
                tx_queue.pop(tx_hash_in_unconfirmed_block.hex(), None)

    def makeup_block(self, complain_votes: LeaderVotes, prev_votes):
        last_block = self.__blockchain.last_unconfirmed_block or self.__blockchain.last_block
        block_height = last_block.header.height + 1
        block_version = self.__blockchain.block_versioner.get_version(block_height)
        block_builder = BlockBuilder.new(block_version, self.__blockchain.tx_versioner)
        block_builder.prev_votes = prev_votes
        if complain_votes and complain_votes.get_result():
            block_builder.leader_votes = complain_votes.votes
        else:
            self.__add_tx_to_block(block_builder)

        return block_builder
