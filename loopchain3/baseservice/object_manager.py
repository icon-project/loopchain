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
"""Facade Class for interface of inner gRPC services"""

from loopchain.components import SingletonMetaClass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from loopchain.peer import PeerService
    from loopchain.channel.channel_service import ChannelService


class ObjectManager(metaclass=SingletonMetaClass):
    """Provides an interface to reference internal objects.
    """

    peer_service: 'PeerService' = None
    channel_service: 'ChannelService' = None
    rest_proxy_service = None
