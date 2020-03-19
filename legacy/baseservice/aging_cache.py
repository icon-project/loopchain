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
"""Custom Dictionary type that has limit size by timestamp"""

import threading
import time

from collections import OrderedDict, MutableMapping


class AgingCacheItem:
    def __init__(self, value, timestamp_seconds, status):
        self.__value = value
        self.__timestamp_seconds = timestamp_seconds
        self.__status = status

    @property
    def value(self):
        return self.__value

    @value.setter
    def value(self, value):
        self.__value = value

    @property
    def timestamp_seconds(self):
        return self.__timestamp_seconds

    @timestamp_seconds.setter
    def timestamp_seconds(self, timestamp_seconds):
        self.__timestamp_seconds = timestamp_seconds

    @property
    def status(self):
        return self.__status

    @status.setter
    def status(self, status):
        self.__status = status


class AgingCache(MutableMapping):
    DEFAULT_ITEM_STATUS = 1  # recommend replace this with custom Enum Type

    def __init__(self, max_age_seconds, items=None, default_item_status=DEFAULT_ITEM_STATUS):
        self.__default_item_status = default_item_status
        self._max_age_seconds = max_age_seconds
        self._lock = threading.Lock()

        now_timestamp_seconds = int(time.time())
        self.d = OrderedDict()
        if items:
            for k, v in items:
                self[k] = AgingCacheItem(v, now_timestamp_seconds, self.__default_item_status)

    @property
    def max_age_seconds(self):
        return self._max_age_seconds

    def pop_item(self):
        return self.d.popitem(last=False)[1].value

    def pop_item_in_status(self, status=DEFAULT_ITEM_STATUS):
        with self._lock:
            operator = (key for key, value in self.d.items() if value.status == status)
            key = next(operator, None)

            return None if key is None else self.d.pop(key)

    def get_item_in_status(self, get_status, set_status):
        with self._lock:
            operator = (value for value in self.d.values() if value.status == get_status)
            item = next(operator, None)

            if item:
                item.status = set_status
                return item.value

            return None

    def get_item_status(self, key):
        return self.d[key].status

    def set_item_status(self, key, status):
        self.d[key].status = status

    def set_item_status_by_time(self, timestamp_seconds, status):
        with self._lock:
            for value in self.d.values():
                if value.timestamp_seconds < timestamp_seconds:
                    value.status = status
                else:
                    break

    def is_empty_in_status(self, status):
        return not self.get_item_in_status(status, status)

    def __first_item(self):
        return next(iter(self.d.items()))[1]

    def __getitem__(self, key):
        with self._lock:
            self.d.move_to_end(key)
            return self.d[key].value

    def __setitem__(self, key, value):
        now_timestamp_seconds = int(time.time())

        with self._lock:
            if key in self.d:
                self.d.move_to_end(key)
            else:
                try:
                    while self.__first_item().timestamp_seconds + self._max_age_seconds <= now_timestamp_seconds:
                        self.d.popitem(last=False)
                except StopIteration:
                    # self.d is empty
                    pass

            self.d[key] = AgingCacheItem(value, int(time.time()), self.__default_item_status)

    def __delitem__(self, key):
        del self.d[key]

    def __iter__(self):
        return iter(self.d)

    def __len__(self):
        return len(self.d)

    def __repr__(self):
        return repr(self.d)
