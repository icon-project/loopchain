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
"""A consensus class based on the Siever algorithm for the loopchain"""
import logging
import threading
from functools import partial

import loopchain.utils as util
from loopchain import configure as conf
from loopchain.baseservice import ObjectManager, TimerService, SlotTimer, Timer
from loopchain.blockchain import ExternalAddress, BlockBuilder, BlockVerifier, TransactionStatusInQueue, Hash32
from loopchain.channel.channel_property import ChannelProperty
from loopchain.peer.consensus_base import ConsensusBase


class ConsensusSiever(ConsensusBase):
    def __init__(self, block_manager):
        super().__init__(block_manager)
        self.__block_generation_timer = None
        self.__lock = threading.Lock()

    def start_timer(self, timer_service):
        self.__block_generation_timer = SlotTimer(
            TimerService.TIMER_KEY_BLOCK_GENERATE,
            conf.INTERVAL_BLOCKGENERATION,
            timer_service,
            self.consensus,
            self.__lock
        )

    def stop(self):
        self.__block_generation_timer.stop()
        self.__stop_broadcast_send_unconfirmed_block_timer()

    async def consensus(self):
        with self.__lock:
            block_builder = self._makeup_block()

            if len(block_builder.transactions) == 0 and not conf.ALLOW_MAKE_EMPTY_BLOCK:
                util.logger.spam(f"tx count in block({len(block_builder.transactions)})")
                return self.__block_generation_timer.call()

            peer_manager = ObjectManager().channel_service.peer_manager

            last_block = self._blockchain.last_block
            block_builder.height = last_block.header.height + 1
            block_builder.prev_hash = last_block.header.hash
            block_builder.next_leader = ExternalAddress.fromhex(peer_manager.get_next_leader_peer().peer_id)
            block_builder.peer_private_key = ObjectManager().channel_service.peer_auth.peer_private_key
            block_builder.confirm_prev_block = (self._made_block_count > 0)

            candidate_block = block_builder.build()
            candidate_block, invoke_results = ObjectManager().channel_service.score_invoke(candidate_block)
            self._blockmanager.set_invoke_results(candidate_block.header.hash.hex(), invoke_results)

            block_verifier = BlockVerifier.new(candidate_block.header.version, self._blockchain.tx_versioner)
            block_verifier.verify(candidate_block, self._blockchain.last_block, self._blockchain)

            logging.debug(f"candidate block : {candidate_block.header}")

            self._blockmanager.candidate_blocks.add_vote(
                candidate_block.header.hash,
                ChannelProperty().group_id,
                ChannelProperty().peer_id,
                True
            )
            self._blockmanager.candidate_blocks.add_block(candidate_block)

            broadcast_func = partial(self._blockmanager.broadcast_send_unconfirmed_block, candidate_block)
            self.__start_broadcast_send_unconfirmed_block_timer(broadcast_func)
            self.count_votes(candidate_block.header.hash)
            self.__block_generation_timer.call()

    def count_votes(self, block_hash: Hash32):
        # count votes
        result = self._blockmanager.candidate_blocks.get_vote_result(block_hash)
        if not result:
            return True  # vote not complete yet

        self.__stop_broadcast_send_unconfirmed_block_timer()

        # vote done
        block = self._blockmanager.candidate_blocks.blocks[block_hash].block
        self._blockmanager.add_block(block)
        self._made_block_count += 1

        pending_tx = self._txQueue.get_item_in_status(TransactionStatusInQueue.normal,
                                                      TransactionStatusInQueue.normal)
        if not pending_tx and not conf.ALLOW_MAKE_EMPTY_BLOCK:
            block_height = block.header.height + 1
            block_version = self._blockchain.block_versioner.get_version(block_height)

            block_builder = BlockBuilder.new(block_version, self._blockchain.tx_versioner)
            block_builder.prev_hash = block.header.hash
            block_builder.height = block.header.height + 1
            block_builder.next_leader = block.header.next_leader
            block_builder.peer_private_key = ObjectManager().channel_service.peer_auth.peer_private_key
            block_builder.confirm_prev_block = True
            empty_block = block_builder.build()

            self._blockmanager.broadcast_send_unconfirmed_block(empty_block)

            ObjectManager().channel_service.state_machine.turn_to_peer()

    # async def _wait_for_voting(self, candidate_block: 'Block'):
    #     while True:
    #         result = self._blockmanager.candidate_blocks.get_vote_result(candidate_block.header.hash)
    #         if result:
    #             return True
    #
    #         timeout_timestamp = candidate_block.header.timestamp + conf.BLOCK_VOTE_TIMEOUT * 1_000_000
    #         timeout = -util.diff_in_seconds(timeout_timestamp)
    #         try:
    #             if timeout < 0:
    #                 raise asyncio.TimeoutError
    #
    #             vote_result = await asyncio.wait_for(self._vote_queue.get(), timeout=timeout)
    #             if vote_result is None:  # sentinel
    #                 return False
    #
    #         except asyncio.TimeoutError:
    #             logging.warning("Timed Out Block not confirmed duration: " +
    #                             str(util.diff_in_seconds(candidate_block.header.timestamp)))
    #             return False

    @staticmethod
    def __start_broadcast_send_unconfirmed_block_timer(broadcast_func):
        timer_key = TimerService.TIMER_KEY_BROADCAST_SEND_UNCONFIRMED_BLOCK
        timer_service = ObjectManager().channel_service.timer_service
        timer_service.add_timer(
            timer_key,
            Timer(
                target=timer_key,
                duration=conf.INTERVAL_BROADCAST_SEND_UNCONFIRMED_BLOCK,
                is_repeat=True,
                is_run_at_start=True,
                callback=broadcast_func
            )
        )

    @staticmethod
    def __stop_broadcast_send_unconfirmed_block_timer():
        timer_key = TimerService.TIMER_KEY_BROADCAST_SEND_UNCONFIRMED_BLOCK
        timer_service = ObjectManager().channel_service.timer_service
        if timer_key in timer_service.timer_list:
            timer_service.stop_timer(timer_key)
