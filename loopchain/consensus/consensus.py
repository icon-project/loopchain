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
from collections import namedtuple

from loopchain import configure as conf
from loopchain import utils as util

from loopchain.blockchain import Block, TransactionStatusInQueue
from loopchain.channel.channel_property import ChannelProperty
from loopchain.consensus import Publisher, Epoch, EpochStatus
from loopchain.baseservice import ObjectManager, CommonThread, Timer, BlockGenerationScheduler
from loopchain.baseservice.aging_cache import AgingCache


class Consensus(CommonThread, Publisher):
    EVENT_COMPLETE_CONSENSUS = "complete_consensus"
    EVENT_MAKE_BLOCK = "make_block"
    EVENT_LEADER_COMPLAIN_F_1 = "leader_complain_f_1"
    EVENT_LEADER_COMPLAIN_2F_1 = "leader_complain_2f_1"

    def __init__(self, channel_service: 'ChannelService', channel: str=None, **kwargs):
        CommonThread.__init__(self)
        Publisher.__init__(self, [
            Consensus.EVENT_COMPLETE_CONSENSUS,
            Consensus.EVENT_LEADER_COMPLAIN_F_1,
            Consensus.EVENT_LEADER_COMPLAIN_2F_1,
            Consensus.EVENT_MAKE_BLOCK])

        self.channel_name = channel
        self.__channel_service = channel_service
        self.__peer_manager = channel_service.peer_manager
        self.__last_epoch: Epoch = None
        self.__precommit_block: Block = None
        self.__epoch: Epoch = None
        self.__leader_id = None
        self.__tx_queue = AgingCache(max_age_seconds=conf.MAX_TX_QUEUE_AGING_SECONDS,
                                     default_item_status=TransactionStatusInQueue.normal)
        self.__sleep_time = None
        self.__run_logic = None
        self.__block_generation_scheduler = BlockGenerationScheduler(self.channel_name)

        self.__init_data()

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

    @property
    def block_generation_scheduler(self):
        return self.__block_generation_scheduler

    def __init_data(self):
        self.__init_sleep_time()
        self.__set_run_logic()

    def __set_run_logic(self):
        if conf.ALLOW_MAKE_EMPTY_BLOCK:
            self.__run_logic = self.__create_block_generation_schedule
        else:
            self.__run_logic = self.__notify

    def __init_sleep_time(self):
        if conf.ALLOW_MAKE_EMPTY_BLOCK:
            self.__sleep_time = conf.INTERVAL_BLOCKGENERATION
        else:
            # self.__sleep_time = conf.SLEEP_SECONDS_IN_SERVICE_LOOP
            self.__sleep_time = 5

    def __create_block_generation_schedule(self):
        util.logger.spam(f"block_manager.py:__create_block_generation_schedule:: CREATE BLOCK GENERATION SCHEDULE")
        Schedule = namedtuple("Schedule", "callback kwargs")
        schedule = Schedule(self._notify, {"event": Consensus.EVENT_MAKE_BLOCK, "tx_queue": self.__tx_queue})
        self.__block_generation_scheduler.add_schedule(schedule)

        time.sleep(conf.INTERVAL_BLOCKGENERATION)

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
            event=Consensus.EVENT_COMPLETE_CONSENSUS,
            precommit_block=self.__precommit_block,
            prev_epoch=self.__last_epoch,
            epoch=self.__epoch,
            tx_queue=self.__tx_queue)

    def get_tx_queue(self) -> AgingCache:
        return self.__tx_queue

    def add_tx_obj(self, tx):
        self.__tx_queue[tx.tx_hash] = tx

    def start(self):
        if conf.ALLOW_MAKE_EMPTY_BLOCK:
            self.__block_generation_scheduler.start()
        CommonThread.start(self)

    def stop(self):
        if conf.ALLOW_MAKE_EMPTY_BLOCK:
            self.__block_generation_scheduler.stop()
        CommonThread.stop(self)

    def run(self, e: threading.Event):
        """Consensus Thread Loop
        Collect transactions every configuration time and request to make a block to proposer.
        :param e:
        :return:
        """

        logging.info(f"channel({self.channel_name}) Consensus thread Start.")
        e.set()

        while self.is_run():
            self.__run_logic()

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

