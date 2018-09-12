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
"""A consensus class based on the LFT algorithm for the loopchain"""

from loopchain.baseservice import ObjectManager, Timer
from loopchain.blockchain import *
from loopchain.peer import candidate_blocks
from loopchain.peer.consensus_base import ConsensusBase


class ConsensusLFT(ConsensusBase):
    """LoopChain 의 Consensus Algorithm 을 표현하는 클래스
    기본 합의 알고리즘으로 Block Generator 에 접속한 모든 PEER 에게 Block 에 대한 투표를 요청한다.
    51% 이상의 투표를 획득하면 해당 블록을 Block Chain 에 추가한다.
    """

    def consensus(self):
        # broadcasting 한 블럭이 검증이 끝났는지 확인한다.
        confirmed_block = None
        try:
            confirmed_block = self._candidate_blocks.get_confirmed_block()
        except candidate_blocks.NoExistBlock as e:
            logging.error(e)
        except candidate_blocks.NotCompleteValidation as e:
            # try re count voters
            logging.warning(f"This block need more validation vote from Peers block hash({str(e.block.block_hash)})")
            self._blockmanager.broadcast_audience_set()

            if util.diff_in_seconds(e.block.time_stamp) > conf.BLOCK_VOTE_TIMEOUT:
                logging.warning("Time Outed Block: " + str(util.diff_in_seconds(e.block.time_stamp)))
                self._candidate_blocks.remove_broken_block(e.block.block_hash)
            else:
                peer_service = ObjectManager().peer_service
                if peer_service is not None:
                    peer_service.reset_voter_count()

                self._candidate_blocks.reset_voter_count(str(e.block.block_hash))
                time.sleep(conf.INTERVAL_WAIT_PEER_VOTE)
        except candidate_blocks.InvalidatedBlock as e:
            # 실패한 투표에 대한 처리
            logging.error("InvalidatedBlock!! hash: " + str(e.block.block_hash))
            logging.debug("InvalidatedBlock!! prev_hash: " + str(e.block.prev_block_hash))

            # 현재 블록은 데이터가 있나?
            logging.debug("This block status: " + str(self._block.confirmed_tx_len))

            self.__throw_out_block(e.block)

        # 검증이 끝난 블럭이 있으면
        if confirmed_block is not None:
            logging.info("Block Validation is Complete hash: " + confirmed_block.block_hash)
            # 현재 블럭에 이전 투표에 대한 기록을 갱신한다.
            self._block.prev_block_confirm = True

            # 검증이 끝나면 BlockChain 에 해당 block 의 block_hash 로 등록 완료
            confirmed_block.block_status = BlockStatus.confirmed
            self._blockmanager.add_block(confirmed_block)

            # 새로운 블럭의 broadcast 를 위해 current_vote_block_hash 를 리셋한다.
            self._current_vote_block_hash = ""

        # logging.debug("current_vote_block_hash: " + current_vote_block_hash)
        # BlockChain 으로 부터 hash 를 받은 하나의 block 만 검증을 위해 broadcast 되어야 한다.
        # 하나의 block 이 검증 성공 또는 실패 시 current_vote_block_hash 는 "" 로 재설정 한다.
        if self._current_vote_block_hash == "":
            # block 에 수집된 tx 가 있으면
            if self._block is not None and self._block.confirmed_tx_len > 0:
                # 검증 받을 블록의 hash 를 생성하고 후보로 등록한다.
                logging.debug("add unconfirmed block to candidate blocks")
                self._block.generate_block(self._candidate_blocks.get_last_block(self._blockchain))
                self._block.sign(ObjectManager().channel_service.peer_auth)
                self._candidate_blocks.add_unconfirmed_block(self._block)

                # logging.warning("blockchain.last_block_hash: " + self._blockchain.last_block.block_hash)
                # logging.warning("block.block_hash: " + self._block.block_hash)
                # logging.warning("block.prev_block_hash: " + self._block.prev_block_hash)

                # 새로운 Block 을 생성하여 다음 tx 을 수집한다.
                self._gen_block()

            # 다음 검증 후보 블럭이 있는지 확인한다.
            candidate_block = self._candidate_blocks.get_candidate_block()
            peer_manager = ObjectManager().channel_service.peer_manager

            if candidate_block is not None:
                # 있으면 해당 블럭을 broadcast 하여 Peer 에게 검증을 요청한다.
                self._current_vote_block_hash = candidate_block.block_hash
                logging.info("candidate block hash: " + self._current_vote_block_hash)

                candidate_block.next_leader_peer = peer_manager.get_next_leader_peer().peer_id
                self._blockmanager.broadcast_send_unconfirmed_block(candidate_block)

                return
            elif self._block is not None and \
                    (self._block.prev_block_confirm is True) and \
                    (self._block.confirmed_tx_len == 0):
                logging.debug("broadcast voting block (has no tx but has a vote result)")

                # 검증할 후보 블럭이 없으면서 이전 블럭이 unconfirmed block 이면 투표가 담긴 빈 블럭을 전송한다.
                self._block.prev_block_hash = confirmed_block.block_hash
                self._block.block_type = BlockType.vote
                self.made_block_count -= 1

                logging.debug(f"made_block_count({self.made_block_count})")

                self._block.next_leader_peer = peer_manager.get_next_leader_peer().peer_id
                self._blockmanager.broadcast_send_unconfirmed_block(self._block)

                # 전송한 빈블럭을 대체한다.
                if self.made_block_count < conf.LEADER_BLOCK_CREATION_LIMIT:  # or not self._txQueue.empty():
                    self._gen_block()
                else:
                    self._stop_gen_block()
                    peer_service.rotate_next_leader(self._channel_name)

        self._makeup_block()

        time.sleep(conf.SLEEP_SECONDS_IN_SERVICE_LOOP)
