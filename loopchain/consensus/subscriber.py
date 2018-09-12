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
"""A Subscriber object for the Observer pattern."""

import logging


class Subscriber:
    def __init__(self, name):
        self.name = name
        self._event_list: list = []  # [(event(str), callback(method))]

    @property
    def event_list(self):
        return self._event_list

    def update(self, message):
        logging.debug(f"{self.name} got a new message from publisher: {message}")
