# Copyright 2019 ICON Foundation
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
"""KeyValueStoreDict classes are components for development"""

import functools

from loopchain.store.key_value_store import KeyValueStoreError
from loopchain.store.key_value_store import KeyValueStoreWriteBatch, KeyValueStoreCancelableWriteBatch, KeyValueStore
from loopchain.store.key_value_store import _validate_args_bytes, _validate_args_bytes_without_first


def _error_convert(func):
    @functools.wraps(func)
    def _wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except RuntimeError as e:
            raise KeyValueStoreError(e)

    return _wrapper


class _KeyValueStoreWriteBatchDict(KeyValueStoreWriteBatch):
    def __init__(self, store_items: dict):
        self._store_items = store_items
        self._batch_items = dict()

    @_validate_args_bytes_without_first
    @_error_convert
    def put(self, key: bytes, value: bytes):
        self._batch_items[key] = value

    @_validate_args_bytes_without_first
    @_error_convert
    def delete(self, key: bytes):
        self._batch_items[key] = None

    @_error_convert
    def clear(self):
        self._batch_items.clear()

    @_error_convert
    def write(self):
        for key, value in self._batch_items.items():
            if value is None:
                try:
                    del self._store_items[key]
                except KeyError:
                    pass
            else:
                self._store_items[key] = value


class _KeyValueStoreCancelableWriteBatchDict(KeyValueStoreCancelableWriteBatch):
    def __init__(self, store: KeyValueStore, store_items: dict):
        super().__init__(store)
        self._store_items = store_items
        self._original_items = dict()

    def _touch(self, key: bytes):
        if key in self._original_items:
            return

        try:
            value = self._store_items[key]
        except KeyError:
            value = None
        self._original_items[key] = value

    def _get_original_touched_item(self):
        for key, value in self._original_items.items():
            yield key, value

    def clear(self):
        super().clear()
        self._original_items.clear()

    def close(self):
        self._original_items: dict = None


class KeyValueStoreDict(KeyValueStore):
    """KeyValueStoreDict class is just for development"""

    def __init__(self, **kwargs):
        self._store_items = dict()

    @_validate_args_bytes_without_first
    @_error_convert
    def get(self, key: bytes, *, default=None, **kwargs) -> bytes:
        if default is not None:
            _validate_args_bytes(default)

        result = self._store_items.get(key, default)
        if result is None:
            raise KeyError(f"Has no value of key({key})")
        return result

    @_validate_args_bytes_without_first
    @_error_convert
    def put(self, key: bytes, value: bytes, *, sync=False, **kwargs):
        self._store_items[key] = value

    @_validate_args_bytes_without_first
    @_error_convert
    def delete(self, key: bytes, *, sync=False, **kwargs):
        try:
            del self._store_items[key]
        except KeyError:
            pass

    @_error_convert
    def close(self):
        if not self._store_items:
            self._store_items = None

    @_error_convert
    def destroy_store(self):
        self.close()

    @_error_convert
    def WriteBatch(self, sync=False) -> KeyValueStoreWriteBatch:
        return _KeyValueStoreWriteBatchDict(self._store_items)

    @_error_convert
    def CancelableWriteBatch(self, sync=False) -> KeyValueStoreCancelableWriteBatch:
        return _KeyValueStoreCancelableWriteBatchDict(self, self._store_items)

    @_error_convert
    def Iterator(self, start_key: bytes = None, stop_key: bytes = None, include_value: bool = True, **kwargs):
        if start_key is not None or stop_key is not None:
            raise ValueError(f"Unsupported arguments which are start_key and stop_key")

        if include_value:
            return self._store_items.items()
        else:
            return self._store_items.keys()
