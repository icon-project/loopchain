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
import json
from functools import partial

import loopchain.utils as util
from loopchain import configure as conf
from loopchain.baseservice import ObjectManager, TimerService, SlotTimer, Timer
from loopchain.blockchain import Epoch
from loopchain.blockchain.votes.v0_1a import BlockVotes
from loopchain.blockchain.blocks import Block
from loopchain.blockchain.types import ExternalAddress, Hash32
from loopchain.blockchain.exception import NotEnoughVotes
from loopchain.channel.channel_property import ChannelProperty
from loopchain.peer.consensus_base import ConsensusBase


class ConsensusSiever(ConsensusBase):
    def __init__(self, block_manager):
        super().__init__(block_manager)
        self.__block_generation_timer = None
        self.__lock = None

        self._loop: asyncio.BaseEventLoop = None
        self._vote_queue: asyncio.Queue = None

    def start_timer(self, timer_service: TimerService):
        self._loop = timer_service.get_event_loop()
        self.__lock = asyncio.Lock(loop=self._loop)
        self.__block_generation_timer = SlotTimer(
            TimerService.TIMER_KEY_BLOCK_GENERATE,
            conf.INTERVAL_BLOCKGENERATION,
            timer_service,
            self.consensus,
            self.__lock,
            self._loop
        )
        self.__block_generation_timer.start(is_run_at_start=conf.ALLOW_MAKE_EMPTY_BLOCK is False)

    def __put_vote(self, vote):
        async def _put():
            if self._vote_queue is not None:
                await self._vote_queue.put(vote)  # sentinel

        asyncio.run_coroutine_threadsafe(_put(), self._loop)

    def stop(self):
        self.__block_generation_timer.stop()
        self.__stop_broadcast_send_unconfirmed_block_timer()

        if self._loop:
            self.__put_vote(None)

    @property
    def is_running(self):
        return self.__block_generation_timer.is_running

    def vote(self, vote):
        if self._loop:
            self.__put_vote(vote)
            return

        util.logger.debug("Cannot vote before starting consensus.")
        # raise RuntimeError("Cannot vote before starting consensus.")

    def __build_candidate_block(self, block_builder, next_leader, vote_result):
        last_block = self._blockchain.last_block
        block_builder.height = last_block.header.height + 1
        block_builder.prev_hash = last_block.header.hash
        block_builder.next_leader = next_leader
        block_builder.signer = ObjectManager().channel_service.peer_auth
        block_builder.confirm_prev_block = vote_result or (self._made_block_count > 0)

        # TODO: This should be changed when IISS is applied.
        block_builder.reps = ObjectManager().channel_service.get_rep_ids()

        return block_builder.build()

    async def __add_block(self, block: Block):
        vote = self._block_manager.candidate_blocks.get_votes(block.header.hash)
        vote_result = await self._wait_for_voting(block)
        if not vote_result:
            raise NotEnoughVotes

        self._block_manager.get_blockchain().add_block(block, confirm_info=vote.votes)
        self._block_manager.candidate_blocks.remove_block(block.header.hash)
        self._blockchain.last_unconfirmed_block = None
        self._made_block_count += 1

    async def __add_block_and_new_epoch(self, block_builder, last_unconfirmed_block: Block):
        """Add Block and start new epoch

        :param block_builder:
        :param last_unconfirmed_block:
        :return: next leader
        """
        await self.__add_block(last_unconfirmed_block)
        self.__remove_duplicate_tx_when_turn_to_leader(block_builder, last_unconfirmed_block)
        self._block_manager.epoch = Epoch.new_epoch(ChannelProperty().peer_id)
        return last_unconfirmed_block.header.next_leader

    def __remove_duplicate_tx_when_turn_to_leader(self, block_builder, last_unconfirmed_block):
        if self.made_block_count == 1:
            for tx_hash_in_unconfirmed_block in last_unconfirmed_block.body.transactions:
                block_builder.transactions.pop(tx_hash_in_unconfirmed_block, None)

    def __makeup_block(self, complained_result):
        prev_block = self._blockchain.last_unconfirmed_block or self._blockchain.last_block
        block_height = prev_block.header.height + 1
        block_version = self._blockchain.block_versioner.get_version(block_height)

        return self._block_manager.epoch.makeup_block(prev_block, block_version, complained_result)

    async def consensus(self):
        util.logger.debug(f"-------------------consensus "
                          f"candidate_blocks({len(self._block_manager.candidate_blocks.blocks)})")
        async with self.__lock:
            if self._block_manager.epoch.leader_id != ChannelProperty().peer_id:
                util.logger.warning(f"This peer is not leader. epoch leader={self._block_manager.epoch.leader_id}")
                return

            self._vote_queue = asyncio.Queue(loop=self._loop)

            if self._block_manager.epoch.round > 0:
                complain_votes = self._block_manager.epoch.complain_votes[self._block_manager.epoch.round - 1]
                # util.logger.info(f"complain_votes : {complain_votes}")

            else:
                complain_votes = None

            last_block = self._blockchain.last_unconfirmed_block or self._blockchain.last_block
            last_block_votes = self.get_votes(last_block.header.hash)

            block_builder = self._block_manager.epoch.makeup_block(complain_votes, last_block_votes)
            vote_result = None
            last_unconfirmed_block = self._blockchain.last_unconfirmed_block
            next_leader = ExternalAddress.fromhex(ChannelProperty().peer_id)

            need_next_call = False
            try:
                complained_result = self._block_manager.epoch.complained_result
                if complained_result:
                    util.logger.spam("consensus block_builder.complained")
                    """
                    confirm_info = self._blockchain.find_confirm_info_by_hash(self._blockchain.last_block.header.hash)
                    if not confirm_info and self._blockchain.last_block.header.height > 0:
                        util.logger.spam("Can't make a block as a leader, this peer will be complained too.")
                        return
                    """
                    # It should be enhanced after coming up for compatibility of versions.
                    self._blockchain.last_unconfirmed_block = None
                    dumped_votes = self._blockchain.find_confirm_info_by_hash(self._blockchain.last_block.header.hash)
                    if block_builder.version == '0.1a':
                        votes = dumped_votes
                    else:
                        votes = BlockVotes.deserialize_votes(json.loads(dumped_votes.decode('utf-8')))

                    block_builder = self._block_manager.epoch.makeup_block(complain_votes, votes)
                    self._made_block_count += 1
                elif self.made_block_count >= (conf.MAX_MADE_BLOCK_COUNT - 1):
                    if last_unconfirmed_block:
                        await self.__add_block(last_unconfirmed_block)
                        peer_manager = ObjectManager().channel_service.peer_manager
                        next_leader = ExternalAddress.fromhex(peer_manager.get_next_leader_peer(
                            current_leader_peer_id=ChannelProperty().peer_id).peer_id)
                        util.logger.spam(f"next_leader in siever({next_leader})")
                    else:
                        util.logger.info(f"This leader already made {self.made_block_count} blocks. "
                                         f"MAX_MADE_BLOCK_COUNT is {conf.MAX_MADE_BLOCK_COUNT} "
                                         f"There is no more right. Consensus loop will return.")
                        return
                elif len(block_builder.transactions) > 0 or conf.ALLOW_MAKE_EMPTY_BLOCK:
                    if last_unconfirmed_block:
                        next_leader = await self.__add_block_and_new_epoch(block_builder, last_unconfirmed_block)
                elif len(block_builder.transactions) == 0 and (
                        last_unconfirmed_block and len(last_unconfirmed_block.body.transactions) > 0):
                    next_leader = await self.__add_block_and_new_epoch(block_builder, last_unconfirmed_block)
                else:
                    need_next_call = True
            except NotEnoughVotes:
                need_next_call = True
            finally:
                if need_next_call:
                    return self.__block_generation_timer.call()

            candidate_block = self.__build_candidate_block(block_builder, next_leader, vote_result)
            candidate_block, invoke_results = ObjectManager().channel_service.score_invoke(candidate_block)
            self._block_manager.set_invoke_results(candidate_block.header.hash.hex(), invoke_results)

            util.logger.spam(f"candidate block : {candidate_block.header}")

            self._blockchain.last_unconfirmed_block = candidate_block
            self._block_manager.epoch = Epoch.new_epoch(next_leader.hex_hx())
            self._block_manager.candidate_blocks.add_block(candidate_block)
            self._block_manager.vote_unconfirmed_block(candidate_block, True)
            self._blockchain.last_unconfirmed_block = candidate_block

            broadcast_func = partial(self._block_manager.broadcast_send_unconfirmed_block, candidate_block)
            self.__start_broadcast_send_unconfirmed_block_timer(broadcast_func)
            if await self._wait_for_voting(candidate_block) is None:
                return

            if next_leader.hex_hx() != ChannelProperty().peer_id:
                util.logger.spam(f"-------------------turn_to_peer "
                                 f"next_leader({next_leader.hex_hx()}) "
                                 f"peer_id({ChannelProperty().peer_id})")
                ObjectManager().channel_service.reset_leader(next_leader.hex_hx())
                ObjectManager().channel_service.turn_on_leader_complain_timer()
            else:
                if self.made_block_count >= conf.MAX_MADE_BLOCK_COUNT:
                    ObjectManager().channel_service.reset_leader(next_leader.hex_hx())
                    
                self._block_manager.epoch = Epoch.new_epoch(next_leader.hex_hx())
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
            votes = self._block_manager.candidate_blocks.get_votes(candidate_block.header.hash)
            util.logger.info(f"Votes : {votes.get_summary()}")
            vote_result = votes.get_result()
            if vote_result is not None or votes.is_completed():
                self.__stop_broadcast_send_unconfirmed_block_timer()
                return vote_result
            await asyncio.sleep(conf.WAIT_SECONDS_FOR_VOTE)

            timeout_timestamp = candidate_block.header.timestamp + conf.BLOCK_VOTE_TIMEOUT * 1_000_000
            timeout = -util.diff_in_seconds(timeout_timestamp)
            try:
                if timeout < 0:
                    raise asyncio.TimeoutError

                if not await asyncio.wait_for(self._vote_queue.get(), timeout=timeout):  # sentinel
                    return None

            except asyncio.TimeoutError:
                util.logger.warning("Timed Out Block not confirmed duration: " +
                                    str(util.diff_in_seconds(candidate_block.header.timestamp)))
                return None

    def get_votes(self, block_hash: Hash32):
        try:
            prev_votes = self._block_manager.candidate_blocks.get_votes(block_hash)
        except KeyError:
            prev_votes = None

        if prev_votes:
            prev_votes_list = prev_votes.votes
        else:
            prev_votes_dumped = self._blockchain.find_confirm_info_by_hash(block_hash)
            try:
                prev_votes_serialized = json.loads(prev_votes_dumped)
            except json.JSONDecodeError:  # handle exception for old votes
                prev_votes_list = []
            except TypeError:  # handle exception for not existing (NoneType) votes
                prev_votes_list = []
            else:
                prev_votes_list = BlockVotes.deserialize_votes(prev_votes_serialized)
        return prev_votes_list

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

