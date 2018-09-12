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
"""A default class of consensus for the loopchain"""

from loopchain.baseservice import ObjectManager
from loopchain.blockchain import *
from loopchain.peer import candidate_blocks
from loopchain.peer.consensus_base import ConsensusBase


class ConsensusDefault(ConsensusBase):
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
            logging.info(e)
            time.sleep(conf.INTERVAL_WAIT_PEER_VOTE)
        except candidate_blocks.InvalidatedBlock as e:
            logging.error("InvalidatedBlock!! " + str(e))
            self._block = Block(channel_name=self._channel_name)
            self._current_vote_block_hash = ""

        if confirmed_block is not None:
            logging.info("Block Validation is Complete hash: " + confirmed_block.block_hash)

            confirmed_block.block_status = BlockStatus.confirmed
            self._blockmanager.add_block(confirmed_block)
            self._current_vote_block_hash = ""

        # logging.debug("current_vote_block_hash: " + current_vote_block_hash)
        # BlockChain 으로 부터 hash 를 받은 하나의 block 만 검증을 위해 broadcast 되어야 한다.
        # 하나의 block 이 검증 성공 또는 실패 시 current_vote_block_hash 는 "" 로 재설정 한다.
        if self._current_vote_block_hash == "":
            # block 에 수집된 tx 가 있으면
            if self._block.confirmed_tx_len > 0:
                # 검증 받을 블록의 hash 를 생성하고 후보로 등록한다.
                logging.debug("add unconfirmed block to candidate blocks")
                self._block.generate_block(self._candidate_blocks.get_last_block(self._blockchain))
                self._candidate_blocks.add_unconfirmed_block(self._block)
                # 새로운 Block 을 생성하여 다음 tx 을 수집한다.
                self._block = Block(channel_name=self._channel_name)

            # 다음 검증 후보 블럭이 있는지 확인한다.
            candidate_block = self._candidate_blocks.get_candidate_block()
            if candidate_block is not None:
                # 있으면 해당 블럭을 broadcast 하여 Peer 에게 검증을 요청한다.
                self._current_vote_block_hash = candidate_block.block_hash
                logging.info("candidate block hash: " + self._current_vote_block_hash)

                candidate_block.next_leader_peer = \
                    ObjectManager().channel_service.peer_manager.get_next_leader_peer().peer_id

                # 생성된 블럭을 투표 요청하기 위해서 broadcast 한다.
                self._blockmanager.broadcast_send_unconfirmed_block(candidate_block)

                # broadcast 를 요청했으면 다음 투표 block 이 있는지 계속 검사하기 위해 return 한다.
                return

        self._makeup_block()

        time.sleep(conf.SLEEP_SECONDS_IN_SERVICE_LOOP)
