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
"""A processing module for consensus algorithm that the loopchain deals with."""

import logging
import threading
import time

from loopchain import configure as conf
from loopchain import utils as util
from loopchain.baseservice import CommonThread, ObjectManager, Timer
from loopchain.baseservice.aging_cache import AgingCache
from loopchain.blockchain import Block, TransactionStatusInQueue
from loopchain.channel.channel_property import ChannelProperty
from loopchain.consensus import Epoch, EpochStatus, Publisher


class Consensus(CommonThread, Publisher):
    def __init__(self, channel_service: 'ChannelService', channel: str=None, **kwargs):
        Publisher.__init__(self, ["complete_consensus", "leader_complain_f_1", "leader_complain_2f_1", "make_block"])
        self.__channel_service = channel_service
        self.__peer_manager = channel_service.peer_manager
        self.channel_name = channel
        self.__last_epoch: Epoch = None
        self.__precommit_block: Block = None
        self.__epoch: Epoch = None
        self.__leader_id = None
        self.__tx_queue = AgingCache(max_age_seconds=conf.MAX_TX_QUEUE_AGING_SECONDS,
                                     default_item_status=TransactionStatusInQueue.normal)

    @property
    def epoch(self):
        return self.__epoch

    @property
    def leader_id(self) -> str:
        return self.__leader_id

    @leader_id.setter
    def leader_id(self, peer_id: str):
        self.__leader_id = peer_id

    @property
    def precommit_block(self):
        return self.__precommit_block

    @precommit_block.setter
    def precommit_block(self, precommit_block):
        self.__precommit_block = precommit_block

    def get_tx_queue(self) -> AgingCache:
        return self.__tx_queue

    def add_tx_obj(self, tx):
        self.__tx_queue[tx.tx_hash] = tx

    def __create_epoch(self):
        quorum, complain_quorum = self.__peer_manager.get_quorum()
        self.__epoch = Epoch(
            prev_epoch=self.__last_epoch,
            precommit_block=self.__precommit_block,
            leader_id=self.__leader_id,
            quorum=quorum,
            complain_quorum=complain_quorum)

        util.logger.spam(f"hrkim>>>consensus :: create_epoch : epoch height : {self.__epoch.block_height}")
        if self.__precommit_block is not None:
            util.logger.spam(f"hrkim>>>consensus :: create_epoch : precommit height : {self.__precommit_block.height}")

        self._notify(
            event="complete_consensus",
            precommit_block=self.__precommit_block,
            prev_epoch=self.__last_epoch,
            epoch=self.__epoch,
            tx_queue=self.__tx_queue)

    def set_new_leader(self, precommit_block: Block):
        peer_order_list: dict = self.__peer_manager.peer_order_list[conf.ALL_GROUP_ID]

        util.logger.spam(f"hrkim==================peer_order_list{peer_order_list}")
        util.logger.spam(f"hrkim==================current_leader({self.__leader_id})")
        util.logger.spam(f"hrkim==================precommit_block.height({precommit_block.height})")

        new_leader_order = None
        for order, peer_id in peer_order_list.items():
            if peer_id == self.__leader_id:
                util.logger.spam(f"hrkim==================current_leader_order({order})")
                new_leader_order = order + 1
                break

        peer_list_size = len(peer_order_list)
        if peer_list_size < new_leader_order or (self.__precommit_block is None and new_leader_order == peer_list_size):
            new_leader_order = 1

        new_leader_id = peer_order_list[new_leader_order]

        util.logger.spam(f"hrkim==================new_leader({new_leader_id})/new_leader_order({new_leader_order})")

        self.__channel_service.set_new_leader(new_leader_id, precommit_block.height)
        self.__leader_id = new_leader_id

    def run(self, e: threading.Event):
        """Consensus Thread Loop
        Collect transactions every configuration time and request to make a block to proposer.
        :param e:
        :return:
        """

        logging.info(f"channel({self.channel_name}) Consensus thread Start.")
        e.set()

        if conf.ALLOW_MAKE_EMPTY_BLOCK:
            sleep_time = conf.INTERVAL_BLOCKGENERATION
        else:
            # sleep_time = conf.SLEEP_SECONDS_IN_SERVICE_LOOP
            sleep_time = 2

        while self.is_run():
            time.sleep(sleep_time)
            self._notify("make_block", tx_queue=self.__tx_queue)

        logging.info(f"channel({self.channel_name}) Consensus thread Ended.")

    def change_epoch(self, prev_epoch: Epoch=None, precommit_block: Block=None):
        logging.debug(f"Consensus:change_epoch:: create new epoch.")
        util.logger.spam(f"prev_epoch: {prev_epoch} / self.__precommit_block: {self.__precommit_block}"
                         f" / precommit_block: {precommit_block}")

        if precommit_block is not None:
            util.logger.spam(f"precommit_block:{precommit_block.height}/{precommit_block.block_hash}")

        if prev_epoch is not None:
            if prev_epoch == self.__epoch and prev_epoch.status == EpochStatus.success:
                self.__precommit_block = precommit_block

            self.__last_epoch = self.__epoch
            self.__epoch = None
        elif self.__precommit_block is None and precommit_block is not None:
            if precommit_block.height > 0:
                self.__leader_id = precommit_block.peer_id
                self.set_new_leader(precommit_block)
            self.__precommit_block = precommit_block

        if self.__precommit_block is not None:
            util.logger.spam(f"hrkim>>>consensus :: change_epoch : before create epoch : precommit height :"
                             f"{self.__precommit_block.height}/{self.__precommit_block.block_hash}")

        self.__create_epoch()

    def set_quorum(self, quorum: int, complain_quorum: int):
        self.__epoch.set_quorum(quorum, complain_quorum)

    def notify_leader_complain_f_1(self):
        pass

    def notify_leader_complain_2f_1(self):
        pass

    def block_sync(self):
        pass

    def start_timer(self, callback):
        timer_key = f"{ChannelProperty().peer_id}:{self.__precommit_block.height}"
        logging.debug(f"start_timer ({timer_key}/{self.__precommit_block.block_hash})")
        timer = Timer(
            target=timer_key,
            duration=conf.TIMEOUT_FOR_PEER_VOTE,
            callback=callback,
            callback_kwargs={"epoch": self.__epoch}
        )
        ObjectManager().channel_service.timer_service.add_timer(timer_key, timer)
