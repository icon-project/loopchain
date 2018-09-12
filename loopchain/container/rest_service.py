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
"""REST Service for Peer"""

from loopchain import utils as util
from loopchain.container import ServerType, Container


class RestService(Container):
    def __init__(self, port, peer_ip=None):
        if peer_ip is None:
            peer_ip = util.get_private_ip()
        Container.__init__(self, port, ServerType.REST_PEER, peer_ip)
        self.start()  # Container Runs RestServer.start()
