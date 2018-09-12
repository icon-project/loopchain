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
""" A help class of the loopchain which provides interface for accessing into engine."""

from loopchain.baseservice import ObjectManager


class ChainHelper:
    """loopchain engine 의 내부 정보를 참조하거나 사용할 수 있는 인터페이스를 제공한다.
    """

    def __init__(self):
        self.loopchain_objects = ObjectManager()

    def get_peer_id(self):
        """현재 동작 중인 Peer 의 id(Peer 고유 식별 값) 를 구한다.

        :return: peer id
        """
        return self.loopchain_objects.peer_service.peer_id
