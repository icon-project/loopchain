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

from loopchain.components import SingletonMetaClass


class ChannelProperty(metaclass=SingletonMetaClass):
    def __init__(self):
        self.name = None
        self.peer_target = None
        self.rest_target = None
        self.radio_station_target = None
        self.amqp_target = None
        self.peer_port = None
        self.peer_id = None
        self.node_type = None
        self.nid = None
