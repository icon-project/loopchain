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

import functools
import urllib.parse
import plyvel

from loopchain.store.key_value_store import KeyValueStoreError
from loopchain.store.key_value_store import KeyValueStoreWriteBatch, KeyValueStoreCancelableWriteBatch, KeyValueStore
from loopchain.store.key_value_store import _validate_args_bytes, _validate_args_bytes_without_first


def _error_convert(func):
    @functools.wraps(func)
    def _wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except plyvel.Error as e:
            raise KeyValueStoreError(e)

    return _wrapper


class _KeyValueStoreWriteBatchPlyvel(KeyValueStoreWriteBatch):
    def __init__(self, db: plyvel.DB, sync: bool):
        self._batch = self._new_batch(db, sync)

    @_error_convert
    def _new_batch(self, db: plyvel.DB, sync: bool):
        return db.write_batch(sync=sync)

    @_validate_args_bytes_without_first
    @_error_convert
    def put(self, key: bytes, value: bytes):
        self._batch.put(key, value)

    @_validate_args_bytes_without_first
    @_error_convert
    def delete(self, key: bytes):
        self._batch.delete(key)

    @_error_convert
    def clear(self):
        self._batch.clear()

    @_error_convert
    def write(self):
        self._batch.write()


class _KeyValueStoreCancelableWriteBatchPlyvel(KeyValueStoreCancelableWriteBatch):
    def __init__(self, store: KeyValueStore, db: plyvel.DB, sync: bool):
        super().__init__(store, sync=sync)
        self._touched_keys = set()
        self._snapshot = db.snapshot()

    def _touch(self, key: bytes):
        self._touched_keys.add(key)

    def _get_original_touched_item(self):
        for key in self._touched_keys:
            try:
                yield key, self._snapshot.get(key)
            except KeyError:
                return key, None

    def clear(self):
        super().clear()
        self._touched_keys.clear()

    def close(self):
        self._snapshot.close()
        self._snapshot = None


class KeyValueStorePlyvel(KeyValueStore):
    def __init__(self, uri: str, **kwargs):
        uri_obj = urllib.parse.urlparse(uri)
        if uri_obj.scheme != 'file':
            raise ValueError(f"Support file path URI only (ex. file:///xxx/xxx). uri={uri}")
        self._path = f"{(uri_obj.netloc if uri_obj.netloc else '')}{uri_obj.path}"
        self._db = self._new_db(self._path, **kwargs)

    @_error_convert
    def _new_db(self, path, **kwargs) -> plyvel.DB:
        return plyvel.DB(path, **kwargs)

    @_validate_args_bytes_without_first
    @_error_convert
    def get(self, key: bytes, *, default=None, **kwargs) -> bytes:
        if default is not None:
            _validate_args_bytes(default)

        result = self._db.get(key, default=default, **kwargs)
        if result is None:
            raise KeyError(f"Has no value of key({key})")
        return result

    @_validate_args_bytes_without_first
    @_error_convert
    def put(self, key: bytes, value: bytes, *, sync=False, **kwargs):
        self._db.put(key, value, sync=sync, **kwargs)

    @_validate_args_bytes_without_first
    @_error_convert
    def delete(self, key: bytes, *, sync=False, **kwargs):
        self._db.delete(key, sync=sync, **kwargs)

    @_error_convert
    def close(self):
        if self._db:
            self._db.close()
            self._db = None

    @_error_convert
    def destroy_store(self):
        self.close()
        plyvel.destroy_db(self._path)

    @_error_convert
    def WriteBatch(self, sync=False) -> KeyValueStoreWriteBatch:
        return _KeyValueStoreWriteBatchPlyvel(self._db, sync=sync)

    @_error_convert
    def CancelableWriteBatch(self, sync=False) -> KeyValueStoreCancelableWriteBatch:
        return _KeyValueStoreCancelableWriteBatchPlyvel(self, self._db, sync=sync)

    @_error_convert
    def Iterator(self, start_key: bytes = None, stop_key: bytes = None, include_value: bool = True, **kwargs):
        if 'start' in kwargs or 'stop' in kwargs:
            raise ValueError(f"Use start_key and stop_key arguments instead of start and stop arguments")

        if 'include_stop' in kwargs:
            include_stop = kwargs['include_stop']
            del kwargs['include_stop']
        elif stop_key:
            include_stop = True
        else:
            include_stop = False

        return self._db.iterator(
            start=start_key,
            stop=stop_key,
            include_stop=include_stop,
            include_value=include_value,
            **kwargs
        )
