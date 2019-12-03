import urllib
from typing import List, Optional

import aioredis
import redis
from aioredis import Redis

from loopchain.store.key_value_store import (
    KeyValueStore,
    KeyValueStoreCancelableWriteBatch,
    KeyValueStoreWriteBatch,
    AsyncKeyValueStore
)


class KeyValueStoreRedis(KeyValueStore):
    def __init__(self, uri: str, **kwargs):
        self._db: redis.Redis = self._new_db(uri, **kwargs)

    def _new_db(self, path, port, **kwargs) -> redis.Redis:
        return redis.Redis("localhost", port)

    def get(self, key: bytes, *, default=None, **kwargs) -> bytes:
        result = self._db.get(key)
        if result is None:
            raise KeyError(f"Has no value of key({key})")
        return result

    def mget(self, keys: List[bytes]) -> List[Optional[bytes]]:
        return self._db.mget(keys)

    def put(self, key: bytes, value: bytes, *, sync=True, **kwargs):
        self._db.set(key, value, **kwargs)

    def delete(self, key: bytes, *, sync=False, **kwargs):
        self._db.delete(key)

    def close(self):
        self._db.close()

    def destroy_store(self):
        pass  # Not used

    def write_batch(self, sync=False) -> KeyValueStoreWriteBatch:
        return _KeyValueStoreWriteBatchRedis(self._db, sync=sync)

    def cancelable_write_batch(self, sync=False) -> KeyValueStoreCancelableWriteBatch:
        pass  # Not used

    def iterator(self, start_key: bytes = None, stop_key: bytes = None, include_value: bool = True, **kwargs):
        pass  # Not used


class _KeyValueStoreWriteBatchRedis(KeyValueStoreWriteBatch):
    def __init__(self, db: redis.Redis, sync: bool):
        self._batch = self._new_batch(db, sync)

    def _new_batch(self, db: redis.Redis, sync: bool) -> redis.client.Pipeline:
        return db.pipeline(transaction=False)

    def put(self, key: bytes, value: bytes):
        self._batch.set(key, value)

    def delete(self, key: bytes):
        self._batch.delete(key)

    def clear(self):
        self._batch.reset()

    def write(self):
        self._batch.execute()


class AsyncStoreRedis(AsyncKeyValueStore):
    """
    """

    def __init__(self, uri: str, **kwargs):
        # FIXME : uri? need cleanup
        uri_obj = urllib.parse.urlparse(uri)
        if uri_obj.scheme != 'file':
            raise ValueError(f"Support file path URI only (ex. file:///xxx/xxx). uri={uri}")
        self._path = f"{(uri_obj.netloc if uri_obj.netloc else '')}{uri_obj.path}"

        self._redis: Redis = self._new_db(self._path, **kwargs)

    async def _new_db(self, _path, param) -> Redis:
        # TODO : return aioredis instance?
        redis = await aioredis.create_redis_pool('redis://localhost')
        return redis

    async def get(self, key: bytes, *, default=None, **kwargs) -> bytes:
        return await self._redis.get(key)

    async def put(self, key: bytes, value: bytes, *, sync=False, **kwargs):
        return await self._redis.set(key, value)

    def delete(self, key: bytes, *, sync=False, **kwargs):
        pass

    async def close(self):
        self._redis.close()
        await self._redis.wait_closed()

    def destroy_store(self):
        pass

    def write_batch(self, sync=False) -> KeyValueStoreWriteBatch:
        pass

    def cancelable_write_batch(self, sync=False) -> KeyValueStoreCancelableWriteBatch:
        pass

    def iterator(self, start_key: bytes = None, stop_key: bytes = None, include_value: bool = True, **kwargs):
        pass
