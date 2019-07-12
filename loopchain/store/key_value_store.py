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


import abc
import functools

from loopchain import utils, configure as conf


class KeyValueStoreError(Exception):
    pass


class KeyValueStoreWriteBatch(abc.ABC):
    """For batch put and delete operations."""

    @abc.abstractmethod
    def put(self, key: bytes, value: bytes):
        """Add or modify a value of the key temporarily.

        :param key:
        :param value:
        """
        raise NotImplementedError("put() function is interface method")

    @abc.abstractmethod
    def delete(self, key: bytes):
        """Delete a record of the key temporarily.

        :param key:
        """
        raise NotImplementedError("delete() function is interface method")

    @abc.abstractmethod
    def clear(self):
        """Clear batch operations."""
        raise NotImplementedError("clear() function is interface method")

    @abc.abstractmethod
    def write(self):
        """Write batch put and delete operations."""
        raise NotImplementedError("write() function is interface method")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is not None:
            self.write()


class KeyValueStoreCancelableWriteBatch(abc.ABC):
    """Cancelable batch put and delete operations.
    It can cancel operations after the operations has been written (called write() function).
    However, It just recover key/value pairs to before KeyValueStoreCancelableWriteBatch instance was made.

    # Store: key1/value1, key2/value2
    batch = key_value_store_instance.CancelableWriteBatch()
    batch.put(key1, value1-1)
    batch.delete(key2)
    batch.write()
    # Store: key1/value-1 (deleted key2)

    # (X) key_value_store_instance.put(key1, value1-2) # will be recovered (key1/value1) after batch is canceled.
    batch.cancel()

    # Store: key1/value1, key2/value2
    """

    def __init__(self, store: 'KeyValueStore', sync=False):
        self._store = store
        self._batch = self._store.WriteBatch(sync=sync)
        self._sync = sync

    def put(self, key: bytes, value: bytes):
        """Add or modify a value of the key temporarily.

        :param key:
        :param value:
        """
        self._batch.put(key, value)
        self._touch(key)

    def delete(self, key: bytes):
        """Delete a record of the key temporarily.

        :param key:
        """
        self._batch.delete(key)
        self._touch(key)

    def clear(self):
        """Clear batch operations."""
        self._batch.clear()

    def write(self):
        """Write batch put and delete operations."""
        self._batch.write()

    def cancel(self):
        """Cancel written operations."""
        batch = self._store.WriteBatch(sync=self._sync)
        for key, value in self._get_original_touched_item():
            if value is None:
                batch.delete(key)
            else:
                batch.put(key, value)
        batch.write()

    @abc.abstractmethod
    def close(self):
        """Close explicitly.
        Will be closed automatically when this instance is deleted.
        """
        raise NotImplementedError("close() function is interface method")

    @abc.abstractmethod
    def _touch(self, key: bytes):
        raise NotImplementedError("_touch() function is interface method")

    @abc.abstractmethod
    def _get_original_touched_item(self):
        # Children have to override function as generator. return key, value
        raise NotImplementedError("_get_touched_item() function is interface method")


class KeyValueStore(abc.ABC):
    STORE_TYPE_PLYVEL = 'plyvel'
    STORE_TYPE_LEVELDB = 'leveldb'
    STORE_TYPE_DICT = 'dict'

    @staticmethod
    def new(uri: str, store_type: str = None, **kwargs) -> 'KeyValueStore':
        if store_type is None:
            store_type = conf.DEFAULT_KEY_VALUE_STORE_TYPE

        utils.logger.info(f"New KeyValueStore. store_type={store_type}, uri={uri}")

        if store_type == KeyValueStore.STORE_TYPE_PLYVEL:
            utils.logger.debug(f"New KeyValueStorePlyvel.")
            from loopchain.store.key_value_store_plyvel import KeyValueStorePlyvel
            return KeyValueStorePlyvel(uri, **kwargs)
        elif store_type == KeyValueStore.STORE_TYPE_LEVELDB:
            utils.logger.warning(f"New KeyValueStoreLevelDb. store_type={store_type}, uri={uri}")
            from loopchain.store.key_value_store_leveldb import KeyValueStoreLevelDb
            return KeyValueStoreLevelDb(uri, **kwargs)
        elif store_type == KeyValueStore.STORE_TYPE_DICT:
            raise ValueError(f"KeyValueStoreDict is just for development.")
            # if you want to use keyValueStoreDict for develop, uncomment below lines
            # from loopchain.store.key_value_store_dict import KeyValueStoreDict
            # return KeyValueStoreDict(**kwargs)
        else:
            raise ValueError(f"store_name is invalid. store_type={store_type}")

    @abc.abstractmethod
    def get(self, key: bytes, *, default=None, **kwargs) -> bytes:
        """Get a value of the key

        :param key:
        :param default: default (bytes)
        :param kwargs:
        :return: a value of the key
        """
        raise NotImplementedError("get() function is interface method")

    @abc.abstractmethod
    def put(self, key: bytes, value: bytes, *, sync=False, **kwargs):
        """Add or modify a value of the key.

        :param key:
        :param value:
        :param sync:
        """
        raise NotImplementedError("put() function is interface method")

    @abc.abstractmethod
    def delete(self, key: bytes, *, sync=False, **kwargs):
        """Delete a record of the key.

        :param key:
        :param sync:
        """
        raise NotImplementedError("delete() function is interface method")

    @abc.abstractmethod
    def close(self):
        """Close explicitly.
        Will be closed automatically when this instance is deleted.
        """
        raise NotImplementedError("close() function is interface method")

    @abc.abstractmethod
    def destroy_store(self):
        """Destroy store data.
        If the data are files, the files may be deleted.
        """
        raise NotImplementedError("destroy_store() function is interface method")

    @abc.abstractmethod
    def WriteBatch(self, sync=False) -> KeyValueStoreWriteBatch:
        """Make a KeyValueStoreWriteBatch instance for this instance"""
        raise NotImplementedError("WriteBatch constructor is not implemented in KeyValueStore class")

    @abc.abstractmethod
    def CancelableWriteBatch(self, sync=False) -> KeyValueStoreCancelableWriteBatch:
        """Make a KeyValueStoreCancelableWriteBatch instance for this instance"""
        raise NotImplementedError("CancelableWriteBatch constructor is not implemented in KeyValueStore class")

    @abc.abstractmethod
    def Iterator(self, start_key: bytes = None, stop_key: bytes = None, include_value: bool = True, **kwargs):
        """Return iterator

        :param start_key: a start key (inclusive)
        :param stop_key: a stop key (inclusive)
        :param include_value: include value (for key, value in store_instance.Iterator(include_value=True):)
        :return: iterator
        """
        # TODO: make KeyValueStoreIterator class. Currently, Iterator can be used in for-loop.
        raise NotImplementedError("Iterator constructor is not implemented in KeyValueStore class")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


def _validate_args_bytes(arg: bytes):
    if not isinstance(arg, bytes):
        raise ValueError(f"Argument type({type(arg)}) is not bytes. argument={arg}")


def _validate_args_bytes_without_first(func):
    @functools.wraps(func)
    def _wrapper(*args, **kwargs):
        for arg in args[1:]:
            _validate_args_bytes(arg)
        return func(*args, **kwargs)

    return _wrapper
