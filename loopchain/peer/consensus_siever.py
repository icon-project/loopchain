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

from loopchain.baseservice import ObjectManager
from loopchain.blockchain import *
from loopchain.peer import candidate_blocks
from loopchain.peer.consensus_base import ConsensusBase


class ConsensusSiever(ConsensusBase):
    """LoopChain 의 Consensus Algorithm 을 표현하는 클래스
    기본 합의 알고리즘으로 Block Generator 에 접속한 모든 PEER 에게 Block 에 대한 투표를 요청한다.
    51% 이상의 투표를 획득하면 해당 블록을 Block Chain 에 추가한다.
    """

    def __throw_out_block(self, failed_block):
        logging.debug(f"Throw out Block!!! {failed_block.height}, {failed_block.block_hash} ")
        # 이전 블럭에 대한 confirm 작업을 생략하도록 설정한다.
        self._block.prev_block_confirm = False

        # 실패한 블럭은 버리고 prev_block_hash 와 block height 를 보정한다.
        self._block.prev_block_hash = failed_block.prev_block_hash
        self._block.height = failed_block.height
        self._block.time_stamp = 0
        self._block_tx_size = 0

        self._current_vote_block_hash = ""
        
    def consensus(self):
        # broadcasting 한 블럭이 검증이 끝났는지 확인한다.
        confirmed_block = None
        try:
            confirmed_block = self._candidate_blocks.get_confirmed_block()
        except candidate_blocks.NoExistBlock as e:
            logging.error(e)
        except candidate_blocks.NotCompleteValidation as e:
            # try re count voters
            logging.warning(f"This block need more validation vote from Peers block "
                            f"hash({str(e.block.block_hash)}) channel({self._channel_name})")

            self._blockmanager.broadcast_audience_set()

            if util.diff_in_seconds(e.block.time_stamp) > conf.BLOCK_VOTE_TIMEOUT:
                logging.warning("Time Outed Block not confirmed duration: " +
                                str(util.diff_in_seconds(e.block.time_stamp)))
                self._candidate_blocks.remove_broken_block(e.block.block_hash)
                self.__throw_out_block(e.block)
            else:
                time.sleep(conf.INTERVAL_WAIT_PEER_VOTE)
        except candidate_blocks.InvalidatedBlock as e:
            # 실패한 투표에 대한 처리
            logging.error("InvalidatedBlock!! hash: " + str(e.block.block_hash))
            logging.debug("InvalidatedBlock!! prev_hash: " + str(e.block.prev_block_hash))

            # 현재 블록은 데이터가 있나?
            logging.debug("This block status: " + str(self._block.confirmed_tx_len))

            self.__throw_out_block(e.block)

        # 검증이 끝난 블럭이 있으면
        result = None
        if confirmed_block is not None:
            logging.info(f"Block Validation is Complete "
                         f"hash({confirmed_block.block_hash}) channel({self._channel_name})")
            # 현재 블럭에 이전 투표에 대한 기록을 갱신한다.
            self._block.prev_block_confirm = True

            # 검증이 끝나면 BlockChain 에 해당 block 의 block_hash 로 등록 완료
            confirmed_block.block_status = BlockStatus.confirmed
            result = self._blockmanager.add_block(confirmed_block)

            # 새로운 블럭의 broadcast 를 위해 current_vote_block_hash 를 리셋한다.
            self._current_vote_block_hash = ""

        block_is_verified = True
        if self._current_vote_block_hash == "":
            if self._block and (conf.ALLOW_MAKE_EMPTY_BLOCK or self._block.confirmed_tx_len > 0):
                if conf.ALLOW_MAKE_EMPTY_BLOCK and \
                        self._txQueue.get_item_in_status(TransactionStatusInQueue.normal,
                                                         TransactionStatusInQueue.normal):
                    self._makeup_block()
                if conf.CHANNEL_OPTION[self._channel_name]['store_valid_transaction_only']:
                    # candidate_block을 broadcasting하기 전에 invoke result verifying 실행
                    self._block.generate_block(self._candidate_blocks.get_last_block(self._blockchain))

                    block_is_verified, need_rebuild, invoke_results = \
                        self._block.verify_through_score_invoke(is_leader=True)

                    old_block_hash = self._block.block_hash
                    if need_rebuild:
                        verified_commit_state = copy.deepcopy(self._block.commit_state)
                        self._block.generate_block(self._candidate_blocks.get_last_block(self._blockchain))
                        assert verified_commit_state == self._block.commit_state

                        ObjectManager().channel_service.score_change_block_hash(block_height=self._block.height,
                                                                                old_block_hash=old_block_hash,
                                                                                new_block_hash=self._block.block_hash)
                    self._blockmanager.set_invoke_results(self._block.block_hash, invoke_results)
                    self._blockmanager.get_blockchain().set_last_commit_state(
                        self._block.height, self._block.commit_state)
                else:
                    # 검증 받을 블록의 hash 를 생성하고 후보로 등록한다.
                    # logging.warning("add unconfirmed block to candidate blocks")
                    self._block.generate_block(self._candidate_blocks.get_last_block(self._blockchain))

                if block_is_verified:
                    self._block.sign(ObjectManager().channel_service.peer_auth)
                    self._candidate_blocks.add_unconfirmed_block(self._block)

                    # 새로운 Block 을 생성하여 다음 tx 을 수집한다.
                    self._gen_block()
                else:
                    failed_block = self._block
                    self._reset_block()
                    self.__throw_out_block(failed_block)

            # 다음 검증 후보 블럭이 있는지 확인한다.
            candidate_block = self._candidate_blocks.get_candidate_block()
            peer_manager = ObjectManager().channel_service.peer_manager

            if candidate_block is not None:
                # 있으면 해당 블럭을 broadcast 하여 Peer 에게 검증을 요청한다.
                self._current_vote_block_hash = candidate_block.block_hash
                logging.info(f"candidate block height: {candidate_block.height}")
                logging.info("candidate block hash: " + self._current_vote_block_hash)

                util.logger.spam(f"consensus_siever:consensus try peer_manager.get_next_leader_peer().peer_id")
                candidate_block.next_leader_peer = peer_manager.get_next_leader_peer().peer_id

                # 생성된 블럭을 투표 요청하기 위해서 broadcast 한다.
                self._blockmanager.broadcast_send_unconfirmed_block(candidate_block)
                time.sleep(conf.SLEEP_SECONDS_IN_SERVICE_LOOP)

                # broadcast 를 요청했으면 다음 투표 block 이 있는지 계속 검사하기 위해 return 한다.
                return result
            elif self._block is not None and \
                    not conf.ALLOW_MAKE_EMPTY_BLOCK and \
                    (self._block.prev_block_confirm is True) and \
                    (self._block.confirmed_tx_len == 0):
                # 검증할 후보 블럭이 없으면서 이전 블럭이 unconfirmed block 이면 투표가 담긴 빈 블럭을 전송한다.
                self._block.prev_block_hash = confirmed_block.block_hash
                self._block.block_type = BlockType.vote
                self.made_block_count -= 1

                logging.debug(f"made_block_count({self.made_block_count})")

                self._block.next_leader_peer = peer_manager.get_next_leader_peer().peer_id

                self._blockmanager.broadcast_send_unconfirmed_block(self._block)

                self._stop_gen_block()
                util.logger.spam(f"consensus_siever:consensus channel({self._channel_name}) "
                                 f"\ntry ObjectManager().peer_service.rotate_next_leader({self._channel_name})")

                ObjectManager().channel_service.state_machine.turn_to_peer()
                # ObjectManager().peer_service.rotate_next_leader(self._channel_name)

        self._makeup_block()

        return result
