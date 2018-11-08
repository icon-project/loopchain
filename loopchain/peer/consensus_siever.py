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

from queue import Queue, Empty
from loopchain.baseservice import ObjectManager
from loopchain.blockchain import *
from loopchain.peer import Vote

from loopchain.peer.consensus_base import ConsensusBase


class ConsensusSiever(ConsensusBase):
    """LoopChain 의 Consensus Algorithm 을 표현하는 클래스
    기본 합의 알고리즘으로 Block Generator 에 접속한 모든 PEER 에게 Block 에 대한 투표를 요청한다.
    51% 이상의 투표를 획득하면 해당 블록을 Block Chain 에 추가한다.
    """
    def __init__(self, block_manager):
        super().__init__(block_manager)

        self._vote_queue = Queue()
        self._did_vote = False

    def stop(self):
        logging.info("Stop Siever")

        self._vote_queue.put(None)  # sentinel
        self._did_vote = False

    def vote(self, vote_block_hash, vote_code, peer_id, group_id):
        self._vote_queue.put((vote_block_hash, vote_code, peer_id, group_id))

    def consensus(self):
        block_builder = self._makeup_block()

        if len(block_builder.transactions) == 0 and not conf.ALLOW_MAKE_EMPTY_BLOCK:
            return

        peer_manager = ObjectManager().channel_service.peer_manager

        last_block = self._blockchain.last_block
        block_builder.height = last_block.header.height + 1
        block_builder.prev_hash = last_block.header.hash
        block_builder.next_leader = Address.fromhex(peer_manager.get_next_leader_peer().peer_id)
        block_builder.peer_private_key = ObjectManager().channel_service.peer_auth.peer_private_key
        block_builder.votes = self._did_vote

        candidate_block = block_builder.build()
        candidate_block, invoke_results = ObjectManager().channel_service.score_invoke(candidate_block)

        block_verifier = BlockVerifier.new("0.1a")
        block_verifier.verify(candidate_block, self._blockchain.last_block, self._blockchain)

        logging.info(f"candidate block height: {candidate_block.header.height}")
        logging.info(f"candidate block hash: {candidate_block.header.hash.hex()}")
        logging.info(f"candidate block next leader: {candidate_block.header.next_leader.hex()}")
        logging.info(f"candidate block votes: {candidate_block.body.votes}")

        vote = Vote(candidate_block.header.hash.hex(), ObjectManager().channel_service.peer_manager)
        vote.add_vote(ChannelProperty().group_id, ChannelProperty().peer_id, True)

        self._blockmanager.broadcast_send_unconfirmed_block(candidate_block)
        success = self._wait_for_voting(candidate_block, vote)
        if not success:
            return

        self._did_vote = True
        self._blockmanager.set_invoke_results(candidate_block.header.hash.hex(), invoke_results)
        self._blockmanager.add_block(candidate_block)

        pending_tx = self._txQueue.get_item_in_status(TransactionStatusInQueue.normal,
                                                      TransactionStatusInQueue.normal)
        if not pending_tx and not conf.ALLOW_MAKE_EMPTY_BLOCK:
            block_builder = BlockBuilder.new("0.1a")
            block_builder.prev_hash = candidate_block.header.hash
            block_builder.height = candidate_block.header.height + 1
            block_builder.next_leader = candidate_block.header.next_leader
            block_builder.peer_private_key = ObjectManager().channel_service.peer_auth.peer_private_key
            block_builder.votes = True
            empty_block = block_builder.build()

            self._blockmanager.broadcast_send_unconfirmed_block(empty_block)
            self._did_vote = False

            ObjectManager().channel_service.state_machine.turn_to_peer()

    def _wait_for_voting(self, candidate_block: 'Block', vote: 'Vote'):
        while True:
            result = vote.get_result(candidate_block.header.hash.hex(), conf.VOTING_RATIO)
            if result:
                return True

            timeout_timestamp = candidate_block.header.timestamp + conf.BLOCK_VOTE_TIMEOUT * 1_000_000
            timeout = -util.diff_in_seconds(timeout_timestamp)
            try:
                if timeout < 0:
                    raise Empty

                vote_result = self._vote_queue.get(timeout=timeout)
                if vote_result is None:  # sentinel
                    return False

                vote_block_hash, vote_code, peer_id, group_id = vote_result
                if vote.target_hash == vote_block_hash:
                    vote.add_vote(group_id, peer_id, vote_code)

            except Empty:
                logging.warning("Timed Out Block not confirmed duration: " +
                                str(util.diff_in_seconds(candidate_block.header.timestamp)))
                return False
