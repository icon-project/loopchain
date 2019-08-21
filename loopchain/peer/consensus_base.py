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
"""A base class of consensus for the loopchain"""

from abc import ABCMeta, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from loopchain.blockchain import BlockChain


class ConsensusBase(metaclass=ABCMeta):
    """LoopChain 의 Consensus Algorithm 을 표현하는 클래스
    """

    def __init__(self, block_manager):
        self._block_manager = block_manager
        self._channel_name = block_manager.channel_name
        self._blockchain: 'BlockChain' = self._block_manager.blockchain

    def stop(self):
        pass

    @abstractmethod
    async def consensus(self):
        """Block Manager 의 Thread Loop 에서 호출 하는 합의 알고리즘
        """
        pass
