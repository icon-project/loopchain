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


class BroadcastCommand:
    SUBSCRIBE = "subscribe"
    UNSUBSCRIBE = "unsubscribe"
    UPDATE_AUDIENCE = "update_audience"
    AUDIENCE_SUBSCRIBE = "audience_subscribe"
    AUDIENCE_UNSUBSCRIBE = "audience_unsubscribe"
    BROADCAST = "broadcast"
    MAKE_SELF_PEER_CONNECTION = "make_self_connection"
    CONNECT_TO_LEADER = "connect_to_leader"
    CREATE_TX = "create_tx"
    STATUS = "status"
