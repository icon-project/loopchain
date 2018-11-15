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
    class Callback:
        def __init__(self, callback, order):
            self.callback = callback
            self.order = order

    def __init__(self, events: list):
        self.event_list: dict = {
            event: [] for event in events
        }

    def __unregister_event(self, event):
        del(self.event_list[event])

    def register_subscriber(self, subscriber: Subscriber):
        if not isinstance(subscriber, Subscriber):
            return False

        for event, callback, order in subscriber.event_list:
            if event not in self.event_list:
                return False

            if callback is None:
                callback = getattr(subscriber, "update")

            callback_list = self.event_list[event]
            callback_list.append(Publisher.Callback(callback, order))
            callback_list.sort(key=lambda c: c.order)

    def unregister_subscriber(self, event, callback: Callback):
        callback_list: list = self.event_list[event]
        callback_list[:] = [cb for cb in callback_list if cb.callback != callback]

        if len(callback_list) == 0:
            self.__unregister_event(event)

    def _notify(self, event_name: str, **kwargs):
        for callback in self.event_list[event_name]:
            callback.callback(**kwargs)

        return True

