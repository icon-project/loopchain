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
"""Adapter for Process Monitor. This adapter can support ManageProcess and ServiceContainer Both"""

from abc import abstractmethod

import loopchain.utils as util
from loopchain.baseservice import Monitor


class MonitorAdapter:

    def __init__(self, channel, process_name):
        self.__process_name = process_name
        self.__channel = channel

    def _append_monitor(self):
        util.logger.spam(f"monitor_adapter:start ({self.__process_name})")
        Monitor().append(channel=self.__channel, process=self)

    @property
    def process_name(self):
        return self.__process_name

    @abstractmethod
    def is_alive(self):
        pass

    @abstractmethod
    def re_start(self):
        pass
