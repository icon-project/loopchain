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
"""A consensus class which hasn't consensus step for the loopchain"""

from loopchain.blockchain import *
from loopchain.peer.consensus_base import ConsensusBase


class ConsensusNone(ConsensusBase):
    """LoopChain 의 Consensus Algorithm 을 표현하는 클래스
    PEER 에 투표를 요청하지 않고 생성한 블록을 바로 Block Chain 에 추가한다.
    해당 블록은 Confirmed Block 으로 PEER 들에게 broadcast 된다.
    """

    def consensus(self):
        self._makeup_block()

        # block 에 수집된 tx 가 있으면
        if self._block.confirmed_tx_len > 0:
            # 블록의 hash 를 생성하고 broadcast 한다.
            self._block.generate_block(self._blockchain.last_block)

            confirmed_block = self._block
            # 검증이 끝나면 BlockChain 에 해당 block 의 block_hash 로 등록 완료
            confirmed_block.block_status = BlockStatus.confirmed
            self._blockchain.add_block(confirmed_block)
            # 해당 block 이 confirm 되었음을 announce 한다.
            # self._blockmanager.broadcast_announce_confirmed_block(confirmed_block.block_hash, confirmed_block)

            # 새로운 Block 을 생성하여 다음 tx 을 수집한다.
            self._block = Block(channel_name=self._channel_name)

        time.sleep(conf.SLEEP_SECONDS_IN_SERVICE_LOOP)
