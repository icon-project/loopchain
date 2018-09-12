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
"""A Publisher object for the Observer pattern."""

import logging

from loopchain.consensus import Subscriber


class Publisher:
    def __init__(self, events: list):
        self.subscribers: dict = {
            event: {} for event in events
        }

    def get_subscribers(self, event):
        return self.subscribers[event]

    def register(self, event, subscriber: Subscriber, callback=None):
        if event not in self.subscribers:
            return False

        if not isinstance(subscriber, Subscriber):
            return False

        if callback is None:
            callback = getattr(subscriber, "update")

        self.subscribers[event][subscriber] = callback

    def multiple_register(self, subscriber: Subscriber):
        for event, callback in subscriber.event_list:
            self.register(event, subscriber, callback)

    def unregister(self, event, subscriber: Subscriber):
        del self.subscribers[event][subscriber]

    def _notify(self, event: str, **kwargs):
        for callback in self.subscribers[event].values():
            callback(**kwargs)
