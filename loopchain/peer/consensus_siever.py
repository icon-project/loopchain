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
import logging
import time

from loopchain import configure as conf, utils as util
from loopchain.baseservice import ObjectManager, Timer, TimerService
from loopchain.blockchain import ExternalAddress, Block, BlockBuilder, BlockVerifier, TransactionStatusInQueue, Vote
from loopchain.channel.channel_property import ChannelProperty
from loopchain.peer.consensus_base import ConsensusBase


class ConsensusSiever(ConsensusBase):
    """LoopChain 의 Consensus Algorithm 을 표현하는 클래스
    기본 합의 알고리즘으로 Block Generator 에 접속한 모든 PEER 에게 Block 에 대한 투표를 요청한다.
    51% 이상의 투표를 획득하면 해당 블록을 Block Chain 에 추가한다.
    """
    def __init__(self, block_manager):
        super().__init__(block_manager)

        self._loop: asyncio.BaseEventLoop = None
        self._vote_queue: asyncio.Queue = None

    def stop(self):
        logging.info("Stop Siever")

        if self._loop:
            coroutine = self._vote_queue.put(None)  # sentinel
            asyncio.run_coroutine_threadsafe(coroutine, self._loop)

    def vote(self, vote_block_hash, vote_code, peer_id, group_id):
        if self._loop:
            coroutine = self._vote_queue.put((vote_block_hash, vote_code, peer_id, group_id))
            asyncio.run_coroutine_threadsafe(coroutine, self._loop)
            return

        #### 바뀐 리더가 이전 리더가 보낸 빈블록에 대한 다른 피어들의 vote 를 수집했다가
        #### 다음 자기가 생성하는 첫블록에 해당 vote 를 담아서 전송해야 한다.
        #### 이때 만약 네트워크가 종료되면 해당 빈블록은 unconfirmed block 상태로 머물다가 삭제 된다.

        raise RuntimeError("Cannot vote before starting consensus.")

    async def consensus(self):
        start_time = time.time()
        empty_block: Block = None

        try:
            self._loop = asyncio.get_event_loop()
            self._vote_queue = asyncio.Queue(loop=self._loop)

            block_builder = self._makeup_block()

            if len(block_builder.transactions) == 0 and not conf.ALLOW_MAKE_EMPTY_BLOCK:
                return

            peer_manager = ObjectManager().channel_service.peer_manager

            last_block = self._blockchain.last_block
            block_builder.height = last_block.header.height + 1
            block_builder.prev_hash = last_block.header.hash
            block_builder.next_leader = ExternalAddress.fromhex(peer_manager.get_next_leader_peer().peer_id)
            block_builder.peer_private_key = ObjectManager().channel_service.peer_auth.peer_private_key
            block_builder.confirm_prev_block = (self._made_block_count > 0)

            candidate_block = block_builder.build()
            candidate_block, invoke_results = ObjectManager().channel_service.score_invoke(candidate_block)

            block_verifier = BlockVerifier.new(candidate_block.header.version, self._blockchain.tx_versioner)
            block_verifier.verify(candidate_block, self._blockchain.last_block, self._blockchain)

            logging.info(f"candidate block : {candidate_block.header}")

            vote = Vote(candidate_block.header.hash.hex(), ObjectManager().channel_service.peer_manager)
            vote.add_vote(ChannelProperty().group_id, ChannelProperty().peer_id, True)

            self._blockmanager.broadcast_send_unconfirmed_block(candidate_block)
            success = await self._wait_for_voting(candidate_block, vote)
            if not success:
                return

            self._blockmanager.set_invoke_results(candidate_block.header.hash.hex(), invoke_results)
            self._blockmanager.add_block(candidate_block)
            self._made_block_count += 1

            pending_tx = self._txQueue.get_item_in_status(TransactionStatusInQueue.normal,
                                                          TransactionStatusInQueue.normal)
            if not pending_tx and not conf.ALLOW_MAKE_EMPTY_BLOCK:
                block_height = candidate_block.header.height + 1
                block_version = self._blockchain.block_versioner.get_version(block_height)

                block_builder = BlockBuilder.new(block_version, self._blockchain.tx_versioner)
                block_builder.prev_hash = candidate_block.header.hash
                block_builder.height = candidate_block.header.height + 1
                block_builder.next_leader = candidate_block.header.next_leader
                block_builder.peer_private_key = ObjectManager().channel_service.peer_auth.peer_private_key
                block_builder.confirm_prev_block = True
                empty_block = block_builder.build()

                self._blockmanager.broadcast_send_unconfirmed_block(empty_block)

                ObjectManager().channel_service.state_machine.turn_to_peer()
        finally:
            if not empty_block:
                elapsed_time = time.time() - start_time
                delay_time = conf.INTERVAL_BLOCKGENERATION - elapsed_time
                self._start_consensus_timer(delay_time)

    async def _wait_for_voting(self, candidate_block: 'Block', vote: 'Vote'):
        while True:
            result = vote.get_result(candidate_block.header.hash.hex(), conf.VOTING_RATIO)
            if result:
                return True

            timeout_timestamp = candidate_block.header.timestamp + conf.BLOCK_VOTE_TIMEOUT * 1_000_000
            timeout = -util.diff_in_seconds(timeout_timestamp)
            try:
                if timeout < 0:
                    raise asyncio.TimeoutError

                vote_result = await asyncio.wait_for(self._vote_queue.get(), timeout=timeout)
                if vote_result is None:  # sentinel
                    return False

                vote_block_hash, vote_code, peer_id, group_id = vote_result
                if vote.target_hash == vote_block_hash:
                    vote.add_vote(group_id, peer_id, vote_code)

            except asyncio.TimeoutError:
                logging.warning("Timed Out Block not confirmed duration: " +
                                str(util.diff_in_seconds(candidate_block.header.timestamp)))
                return False

    def _start_consensus_timer(self, delay):
        if delay < 0:
            delay = 0

        timer_key = TimerService.TIMER_KEY_BLOCK_GENERATE
        timer_service = ObjectManager().channel_service.timer_service
        timer_service.add_timer(
            timer_key,
            Timer(
                target=timer_key,
                duration=delay,
                is_repeat=False,
                callback=self.consensus
            )
        )
