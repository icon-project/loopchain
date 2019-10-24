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
import leveldb

from loopchain.store.key_value_store import KeyValueStoreError
from loopchain.store.key_value_store import KeyValueStoreWriteBatch, KeyValueStoreCancelableWriteBatch, KeyValueStore
from loopchain.store.key_value_store import _validate_args_bytes, _validate_args_bytes_without_first


def _error_convert(func):
    @functools.wraps(func)
    def _wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except leveldb.LevelDBError as e:
            raise KeyValueStoreError(e)

    return _wrapper


class _KeyValueStoreWriteBatchLevelDb(KeyValueStoreWriteBatch):
    def __init__(self, db: leveldb.LevelDB, sync: bool):
        self._db = db
        self._batch = self._new_batch()
        self._sync = sync

    @_error_convert
    def _new_batch(self):
        return leveldb.WriteBatch()

    @_validate_args_bytes_without_first
    @_error_convert
    def put(self, key: bytes, value: bytes):
        self._batch.Put(key, value)

    @_validate_args_bytes_without_first
    @_error_convert
    def delete(self, key: bytes):
        self._batch.Delete(key)

    @_error_convert
    def clear(self):
        del self._batch
        self._batch = self._new_batch()

    @_error_convert
    def write(self):
        self._db.Write(self._batch, sync=self._sync)


class _KeyValueStoreCancelableWriteBatchLevelDb(KeyValueStoreCancelableWriteBatch):
    def __init__(self, store: KeyValueStore, db: leveldb.LevelDB, sync: bool):
        super().__init__(store, sync=sync)
        self._touched_keys = set()
        self._snapshot = db.CreateSnapshot()

    def _touch(self, key: bytes):
        self._touched_keys.add(key)

    def _get_original_touched_item(self):
        for key in self._touched_keys:
            try:
                yield key, self._snapshot.Get(key, default=None)
            except KeyError:
                return key, None

    def clear(self):
        super().clear()
        self._touched_keys.clear()

    def close(self):
        del self._snapshot
        self._snapshot = None


class KeyValueStoreLevelDb(KeyValueStore):
    def __init__(self, uri: str, **kwargs):
        uri_obj = urllib.parse.urlparse(uri)
        if uri_obj.scheme != 'file':
            raise ValueError(f"Support file path URI only (ex. file:///xxx/xxx). uri={uri}")
        self._path = f"{(uri_obj.netloc if uri_obj.netloc else '')}{uri_obj.path}"
        self._db = self._new_db(self._path, **kwargs)

    @_error_convert
    def _new_db(self, path, **kwargs) -> leveldb.LevelDB:
        return leveldb.LevelDB(path, **kwargs)

    @_validate_args_bytes_without_first
    @_error_convert
    def get(self, key, *, default=None, **kwargs) -> bytes:
        if default is not None:
            _validate_args_bytes(default)

        try:
            return bytes(self._db.Get(key, **kwargs))
        except KeyError:
            if default is not None:
                return default
            raise KeyError(f"Has no value of key({key})")

    @_validate_args_bytes_without_first
    @_error_convert
    def put(self, key, value, *, sync=False, **kwargs):
        self._db.Put(key, value, sync=sync, **kwargs)

    @_validate_args_bytes_without_first
    @_error_convert
    def delete(self, key, *, sync=False, **kwargs):
        self._db.Delete(key, sync=sync, **kwargs)

    @_error_convert
    def close(self):
        if self._db:
            del self._db
            self._db = None

    @_error_convert
    def destroy_store(self):
        self.close()
        leveldb.DestroyDB(self._path)

    @_error_convert
    def WriteBatch(self, sync=False) -> KeyValueStoreWriteBatch:
        return _KeyValueStoreWriteBatchLevelDb(self._db, sync)

    @_error_convert
    def CancelableWriteBatch(self, sync=False) -> KeyValueStoreCancelableWriteBatch:
        return _KeyValueStoreCancelableWriteBatchLevelDb(self, self._db, sync)

    @_error_convert
    def Iterator(self, start_key: bytes = None, stop_key: bytes = None, include_value: bool = True, **kwargs):
        if 'key_from' in kwargs or 'key_to' in kwargs:
            raise ValueError(f"Use start_key and stop_key arguments instead of key_from and key_to arguments")

        return self._db.RangeIter(key_from=start_key, key_to=stop_key, include_value=include_value, **kwargs)
