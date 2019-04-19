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

import asyncio
import threading
from functools import partial

import loopchain.utils as util
from loopchain import configure as conf
from loopchain.baseservice import ObjectManager, TimerService, SlotTimer, Timer
from loopchain.blockchain import ExternalAddress, Vote, Block, Epoch
from loopchain.channel.channel_property import ChannelProperty
from loopchain.peer.consensus_base import ConsensusBase


class ConsensusSiever(ConsensusBase):
    def __init__(self, block_manager):
        super().__init__(block_manager)
        self.__block_generation_timer = None
        self.__lock = threading.Lock()

        self._loop: asyncio.BaseEventLoop = None
        self._vote_queue: asyncio.Queue = None

    def start_timer(self, timer_service):
        self.__block_generation_timer = SlotTimer(
            TimerService.TIMER_KEY_BLOCK_GENERATE,
            conf.INTERVAL_BLOCKGENERATION,
            timer_service,
            self.consensus,
            self.__lock
        )
        self.__block_generation_timer.start()

    def stop(self):
        self.__block_generation_timer.stop()
        self.__stop_broadcast_send_unconfirmed_block_timer()

        if self._loop:
            coroutine = self._vote_queue.put(None)  # sentinel
            asyncio.run_coroutine_threadsafe(coroutine, self._loop)

    def vote(self, vote_block_hash, vote_code, peer_id, group_id):
        if self._loop:
            coroutine = self._vote_queue.put((vote_block_hash, vote_code, peer_id, group_id))
            asyncio.run_coroutine_threadsafe(coroutine, self._loop)
            return

        util.logger.debug("Cannot vote before starting consensus.")
        # raise RuntimeError("Cannot vote before starting consensus.")

    def __build_candidate_block(self, block_builder, next_leader, vote_result):
        last_block = self._blockchain.last_block
        block_builder.height = last_block.header.height + 1
        block_builder.prev_hash = last_block.header.hash
        block_builder.next_leader = next_leader
        block_builder.peer_private_key = ObjectManager().channel_service.peer_auth.private_key
        block_builder.confirm_prev_block = vote_result or (self._made_block_count > 0)

        # TODO: This should be changed when IISS is applied.
        block_builder.reps = ObjectManager().channel_service.get_rep_ids()

        return block_builder.build()

    async def consensus(self):
        util.logger.debug(f"-------------------consensus "
                          f"candidate_blocks({len(self._block_manager.candidate_blocks.blocks)})")
        with self.__lock:
            self._loop = asyncio.get_event_loop()
            self._vote_queue = asyncio.Queue(loop=self._loop)

            complained_result = self._block_manager.epoch.complained_result
            block_builder = self._block_manager.epoch.makeup_block(complained_result)
            vote_result = None
            last_unconfirmed_block = self._blockchain.last_unconfirmed_block
            next_leader = ExternalAddress.fromhex(ChannelProperty().peer_id)

            if complained_result:
                util.logger.spam("consensus block_builder.complained")
                confirm_info = self._blockchain.find_confirm_info_by_hash(self._blockchain.last_block.header.hash)
                if not confirm_info and self._blockchain.last_block.header.height > 0:
                    util.logger.spam("Can't make a block as a leader, this peer will be complained too.")
                    return

                self._made_block_count += 1
            elif len(block_builder.transactions) > 0:
                util.logger.spam(f"consensus len(block_builder.transactions) > 0")
                if last_unconfirmed_block:
                    if (
                            len(last_unconfirmed_block.body.transactions) > 0 or
                            last_unconfirmed_block.header.complained
                    ) or (
                            len(last_unconfirmed_block.body.transactions) == 0 and
                            last_unconfirmed_block.header.peer_id.hex_hx() != ChannelProperty().peer_id
                    ):
                        vote = self._block_manager.candidate_blocks.get_vote(last_unconfirmed_block.header.hash)
                        vote_result = await self._wait_for_voting(last_unconfirmed_block)
                        if not vote_result:
                            return self.__block_generation_timer.call()

                        self.__add_block(last_unconfirmed_block, vote)

                        next_leader = last_unconfirmed_block.header.next_leader
            else:
                if (
                        last_unconfirmed_block
                ) and (
                        len(last_unconfirmed_block.body.transactions) > 0 or
                        last_unconfirmed_block.header.complained
                ):
                    vote = self._block_manager.candidate_blocks.get_vote(last_unconfirmed_block.header.hash)
                    vote_result = await self._wait_for_voting(last_unconfirmed_block)
                    if not vote_result:
                        return self.__block_generation_timer.call()

                    self.__add_block(last_unconfirmed_block, vote)

                    peer_manager = ObjectManager().channel_service.peer_manager
                    next_leader = ExternalAddress.fromhex(peer_manager.get_next_leader_peer(
                        current_leader_peer_id=ChannelProperty().peer_id).peer_id)
                else:
                    return self.__block_generation_timer.call()

            candidate_block = self.__build_candidate_block(block_builder, next_leader, vote_result)
            candidate_block, invoke_results = ObjectManager().channel_service.score_invoke(candidate_block)
            self._block_manager.set_invoke_results(candidate_block.header.hash.hex(), invoke_results)

            util.logger.spam(f"candidate block : {candidate_block.header}")

            self._block_manager.vote_unconfirmed_block(candidate_block.header.hash, True)
            self._block_manager.candidate_blocks.add_block(candidate_block)
            self._blockchain.last_unconfirmed_block = candidate_block

            broadcast_func = partial(self._block_manager.broadcast_send_unconfirmed_block, candidate_block)

            self.__start_broadcast_send_unconfirmed_block_timer(broadcast_func)
            if await self._wait_for_voting(candidate_block) is None:
                return

            self._block_manager.epoch = Epoch.new_epoch(next_leader.hex_hx())
            if len(candidate_block.body.transactions) == 0 and not conf.ALLOW_MAKE_EMPTY_BLOCK and \
                    next_leader.hex_hx() != ChannelProperty().peer_id:
                util.logger.spam(f"-------------------turn_to_peer "
                                 f"next_leader({next_leader.hex_hx()}) "
                                 f"peer_id({ChannelProperty().peer_id})")
                ObjectManager().channel_service.reset_leader(next_leader.hex_hx())
            else:
                if not conf.ALLOW_MAKE_EMPTY_BLOCK:
                    self.__block_generation_timer.call_instantly()
                else:
                    self.__block_generation_timer.call()

    async def _wait_for_voting(self, candidate_block: 'Block'):
        """Waiting validator's vote for the candidate_block.

        :param candidate_block:
        :return: vote_result or None
        """
        # util.logger.notice(f"_wait_for_voting block({candidate_block.header.hash})")
        while True:
            vote = self._block_manager.candidate_blocks.get_vote(candidate_block.header.hash)
            vote_result = vote.get_result(candidate_block.header.hash.hex(), conf.VOTING_RATIO)
            if vote_result:
                self.__stop_broadcast_send_unconfirmed_block_timer()
                return vote_result
            await asyncio.sleep(conf.WAIT_SECONDS_FOR_VOTE)

            timeout_timestamp = candidate_block.header.timestamp + conf.BLOCK_VOTE_TIMEOUT * 1_000_000
            timeout = -util.diff_in_seconds(timeout_timestamp)
            try:
                if timeout < 0:
                    raise asyncio.TimeoutError

                if await asyncio.wait_for(self._vote_queue.get(), timeout=timeout) is None:  # sentinel
                    return None

            except asyncio.TimeoutError:
                util.logger.warning("Timed Out Block not confirmed duration: " +
                                    str(util.diff_in_seconds(candidate_block.header.timestamp)))
                return None

    def __add_block(self, block: Block, vote: Vote):
        self._block_manager.get_blockchain().add_block(block, vote)
        self._block_manager.candidate_blocks.remove_block(block.header.hash)
        self._blockchain.last_unconfirmed_block = None
        self._made_block_count += 1

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
