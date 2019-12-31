# Copyright 2019 ICON Foundation
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
from typing import TYPE_CHECKING, Optional

import loopchain.utils as util
from loopchain import configure as conf
from loopchain.baseservice import ObjectManager, TimerService, SlotTimer, Timer
from loopchain.blockchain.blocks import Block
from loopchain.blockchain.exception import NotEnoughVotes, ThereIsNoCandidateBlock, InvalidBlock
from loopchain.blockchain.types import ExternalAddress, Hash32
from loopchain.blockchain.votes import Votes
from loopchain.channel.channel_property import ChannelProperty
from loopchain.peer.consensus_base import ConsensusBase

if TYPE_CHECKING:
    from loopchain.blockchain import BlockBuilder
    from loopchain.peer import BlockManager


class ConsensusSiever(ConsensusBase):
    def __init__(self, block_manager: 'BlockManager'):
        super().__init__(block_manager)
        self.__block_generation_timer = None
        self.__lock = None

        self._loop: asyncio.BaseEventLoop = None
        self._vote_queue: asyncio.Queue = None

        util.logger.debug(f"Stop previous broadcast!")
        self.stop_broadcast_send_unconfirmed_block_timer()

    def start_timer(self, timer_service: TimerService):
        self._loop = timer_service.get_event_loop()
        self.__lock = asyncio.Lock(loop=self._loop)
        self.__block_generation_timer = SlotTimer(
            TimerService.TIMER_KEY_BLOCK_GENERATE,
            conf.INTERVAL_BLOCKGENERATION,
            timer_service,
            self.consensus,
            self.__lock,
            self._loop,
            call_instantly=not conf.ALLOW_MAKE_EMPTY_BLOCK
        )
        self.__block_generation_timer.start(is_run_at_start=conf.ALLOW_MAKE_EMPTY_BLOCK is False)

    def __put_vote(self, vote):
        async def _put():
            if self._vote_queue is not None:
                await self._vote_queue.put(vote)  # sentinel

        asyncio.run_coroutine_threadsafe(_put(), self._loop)

    def stop(self):
        self.__block_generation_timer.stop()
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

    def __build_candidate_block(self, block_builder: 'BlockBuilder'):
        last_block = self._blockchain.last_block
        block_builder.height = last_block.header.height + 1
        block_builder.prev_hash = last_block.header.hash
        block_builder.signer = ChannelProperty().peer_auth
        block_builder.confirm_prev_block = (block_builder.version == '0.1a')

        if block_builder.version == '0.1a' or (not block_builder.next_leader and not block_builder.reps):
            block_builder.next_leader = ExternalAddress.fromhex_address(self._block_manager.epoch.leader_id)
            block_builder.reps = self._block_manager.epoch.reps

        try:
            if block_builder.next_reps is None:
                # to build temporary block (version >= 0.4)
                block_builder.next_reps = []
        except AttributeError as e:
            util.logger.info(f"block_version = {block_builder.version} : {e}")

        return block_builder.build()

    async def __add_block(self, block: Block):
        vote = await self._wait_for_voting(block)
        if not vote:
            raise NotEnoughVotes
        elif not vote.get_result():
            raise InvalidBlock

        self._blockchain.add_block(block, confirm_info=vote.votes)
        self._block_manager.candidate_blocks.remove_block(block.header.hash)
        self._blockchain.last_unconfirmed_block = None

    def _makeup_new_block(self, block_version, complain_votes, block_hash):
        self._blockchain.last_unconfirmed_block = None
        dumped_votes = self._blockchain.find_confirm_info_by_hash(block_hash)

        if block_version == '0.1a':
            votes = dumped_votes
        else:
            votes_class = Votes.get_block_votes_class(block_version)
            votes = votes_class.deserialize_votes(json.loads(dumped_votes.decode('utf-8')))

        return self._block_manager.epoch.makeup_block(complain_votes, votes)

    def __get_complaint_votes(self):
        if self._block_manager.epoch.complained_result:
            return self._block_manager.epoch.complain_votes[self._block_manager.epoch.round - 1]
        return None

    async def consensus(self):
        util.logger.debug(f"-------------------consensus-------------------")
        async with self.__lock:
            if self._block_manager.epoch.leader_id != ChannelProperty().peer_id:
                util.logger.warning(
                    f"This peer is not leader. epoch leader={self._block_manager.epoch.leader_id}")

            self._vote_queue = asyncio.Queue(loop=self._loop)
            complain_votes = self.__get_complaint_votes()
            complained_result = self._block_manager.epoch.complained_result
            if complained_result:
                self._blockchain.last_unconfirmed_block = None
            else:
                self._block_manager.epoch.remove_duplicate_tx_when_turn_to_leader()

            last_block_vote_list = await self.__get_votes(self._blockchain.latest_block.header.hash)
            if last_block_vote_list is None:
                return

            last_unconfirmed_block: Optional[Block] = self._blockchain.last_unconfirmed_block
            last_block_header = self._blockchain.last_block.header

            if last_block_header.prep_changed:
                new_term = last_unconfirmed_block is None
            else:
                new_term = False

            if last_unconfirmed_block and not last_block_vote_list and not new_term:
                return

            # unrecorded_block means the last block of term to add prep changed block.
            if last_unconfirmed_block and last_unconfirmed_block.header.prep_changed:
                first_leader_of_term = self._blockchain.find_preps_ids_by_roothash(
                    last_unconfirmed_block.header.revealed_next_reps_hash)[0]
                is_unrecorded_block = ChannelProperty().peer_address != first_leader_of_term
            else:
                is_unrecorded_block = False

            skip_add_tx = is_unrecorded_block or complained_result
            block_builder = self._block_manager.epoch.makeup_block(
                complain_votes, last_block_vote_list, new_term, skip_add_tx)
            need_next_call = False
            try:
                if complained_result or new_term:
                    util.logger.spam("consensus block_builder.complained or new term")
                    """
                    confirm_info = self._blockchain.find_confirm_info_by_hash(self._blockchain.last_block.header.hash)
                    if not confirm_info and self._blockchain.last_block.header.height > 0:
                        util.logger.spam("Can't make a block as a leader, this peer will be complained too.")
                        return
                    """
                    block_builder = self._makeup_new_block(block_builder.version,
                                                           complain_votes,
                                                           self._blockchain.last_block.header.hash)
                elif self._blockchain.my_made_block_count == (conf.MAX_MADE_BLOCK_COUNT - 2):
                    # (conf.MAX_MADE_BLOCK_COUNT - 2) means if made_block_count is 8,
                    # but after __add_block, it becomes 9
                    # so next unconfirmed block height is 10 (last).
                    if last_unconfirmed_block:
                        await self.__add_block(last_unconfirmed_block)
                    else:
                        util.logger.info(f"This leader already made "
                                         f"{self._blockchain.my_made_block_count} blocks. "
                                         f"MAX_MADE_BLOCK_COUNT is {conf.MAX_MADE_BLOCK_COUNT} "
                                         f"There is no more right. Consensus loop will return.")
                        return
                elif len(block_builder.transactions) == 0 and not conf.ALLOW_MAKE_EMPTY_BLOCK and \
                        (last_unconfirmed_block and len(last_unconfirmed_block.body.transactions) == 0):
                    need_next_call = True
                elif last_unconfirmed_block:
                    await self.__add_block(last_unconfirmed_block)
            except (NotEnoughVotes, InvalidBlock):
                need_next_call = True
            except ThereIsNoCandidateBlock:
                util.logger.warning(f"There is no candidate block.")
                return
            finally:
                if need_next_call:
                    return self.__block_generation_timer.call()

            util.logger.spam(f"self._block_manager.epoch.leader_id: {self._block_manager.epoch.leader_id}")
            candidate_block = self.__build_candidate_block(block_builder)
            candidate_block, invoke_results = self._blockchain.score_invoke(
                candidate_block, self._blockchain.latest_block,
                is_block_editable=True, is_unrecorded_block=is_unrecorded_block)

            util.logger.spam(f"candidate block : {candidate_block.header}")
            self._block_manager.candidate_blocks.add_block(
                candidate_block, self._blockchain.find_preps_addresses_by_header(candidate_block.header))
            self.__broadcast_block(candidate_block)

            if is_unrecorded_block:
                self._blockchain.last_unconfirmed_block = None
            else:
                self._block_manager.vote_unconfirmed_block(candidate_block,
                                                           self._block_manager.epoch.round,
                                                           True)
                self._blockchain.last_unconfirmed_block = candidate_block
                try:
                    await self._wait_for_voting(candidate_block)
                except NotEnoughVotes:
                    return

            if not candidate_block.header.prep_changed:
                if (self._blockchain.made_block_count_reached_max(self._blockchain.last_block) or
                        self._block_manager.epoch.leader_id != ChannelProperty().peer_id):
                    ObjectManager().channel_service.reset_leader(self._block_manager.epoch.leader_id)

            self.__block_generation_timer.call()

    async def _wait_for_voting(self, block: 'Block'):
        """Waiting validator's vote for the candidate_block.

        :param block:
        :return: vote_result or None
        """
        while True:
            vote = self._block_manager.candidate_blocks.get_votes(block.header.hash, self._block_manager.epoch.round)
            if not vote:
                raise ThereIsNoCandidateBlock

            util.logger.info(f"Votes : {vote.get_summary()}")
            if vote.is_completed():
                self._block_manager.epoch.complained_result = None
                self.stop_broadcast_send_unconfirmed_block_timer()
                return vote

            await asyncio.sleep(conf.WAIT_SECONDS_FOR_VOTE)

            try:
                timeout = self.__check_timeout(block)
                if not await asyncio.wait_for(self._vote_queue.get(), timeout=timeout):  # sentinel
                    raise NotEnoughVotes
            except (TimeoutError, asyncio.TimeoutError):
                util.logger.warning("Timed Out Block not confirmed duration: " +
                                    str(util.diff_in_seconds(block.header.timestamp)))
                raise NotEnoughVotes

    def __check_timeout(self, block):
        timeout_timestamp = block.header.timestamp + conf.BLOCK_VOTE_TIMEOUT * 1_000_000
        timeout = -util.diff_in_seconds(timeout_timestamp)

        if timeout < 0:
            raise TimeoutError
        return timeout

    async def __get_votes(self, block_hash: Hash32):
        try:
            prev_votes = self._block_manager.candidate_blocks.get_votes(block_hash, self._block_manager.epoch.round)
        except KeyError as e:
            util.logger.spam(f"There is no block in candidates list: {e}")
            prev_votes = None

        if prev_votes:
            try:
                last_unconfirmed_block = self._blockchain.last_unconfirmed_block
                if last_unconfirmed_block is None:
                    warning_msg = f"There is prev_votes({prev_votes}). But I have no last_unconfirmed_block."
                    if self._blockchain.find_block_by_hash32(block_hash):
                        warning_msg += "\nBut already added block so  no longer have to wait for the vote."
                        # TODO An analysis of the cause of this situation is necessary.
                        util.logger.notice(warning_msg)
                        self._block_manager.candidate_blocks.remove_block(block_hash)
                    else:
                        util.logger.warning(warning_msg)
                    return None

                self.__check_timeout(last_unconfirmed_block)
                if not prev_votes.is_completed():
                    self.__broadcast_block(last_unconfirmed_block)
                    if await self._wait_for_voting(last_unconfirmed_block) is None:
                        return None

                prev_votes_list = prev_votes.votes
            except TimeoutError:
                util.logger.warning(f"Timeout block of hash : {block_hash}")
                if self._block_manager.epoch.complained_result:
                    self._blockchain.last_unconfirmed_block = None
                self.stop_broadcast_send_unconfirmed_block_timer()
                ObjectManager().channel_service.state_machine.switch_role()
                return None
            except NotEnoughVotes:
                if last_unconfirmed_block:
                    util.logger.warning(f"The last unconfirmed block has not enough votes. {block_hash}")
                    return None
                else:
                    util.exit_and_msg(f"The block that has not enough votes added to the blockchain.")
        else:
            prev_votes_dumped = self._blockchain.find_confirm_info_by_hash(block_hash)
            try:
                prev_votes_serialized = json.loads(prev_votes_dumped)
            except json.JSONDecodeError as e:  # handle exception for old votes
                util.logger.spam(f"{e}")
                prev_votes_list = []
            except TypeError as e:  # handle exception for not existing (NoneType) votes
                util.logger.spam(f"{e}")
                prev_votes_list = []
            else:
                version = self._blockchain.block_versioner.get_version(self._block_manager.epoch.height)
                prev_votes_list = Votes.get_block_votes_class(version).deserialize_votes(prev_votes_serialized)
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
                repeat_timeout=conf.TIMEOUT_FOR_LEADER_COMPLAIN,
                is_run_at_start=True,
                callback=broadcast_func
            )
        )

    @staticmethod
    def stop_broadcast_send_unconfirmed_block_timer():
        timer_key = TimerService.TIMER_KEY_BROADCAST_SEND_UNCONFIRMED_BLOCK
        timer_service = ObjectManager().channel_service.timer_service
        if timer_key in timer_service.timer_list:
            timer_service.stop_timer(timer_key)

    def __broadcast_block(self, block: 'Block'):
        broadcast_func = partial(self._block_manager.broadcast_send_unconfirmed_block,
                                 block,
                                 self._block_manager.epoch.round)
        self.__start_broadcast_send_unconfirmed_block_timer(broadcast_func)
