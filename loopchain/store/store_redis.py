import asyncio
import functools

import aioredis
from aioredis import Redis, RedisError

from loopchain.store.key_value_store import (
    KeyValueStore,
    KeyValueStoreCancelableWriteBatch,
    KeyValueStoreWriteBatch,
    AsyncKeyValueStore,
    KeyValueStoreError,
    _validate_args_bytes_without_first)


class StoreRedis(KeyValueStore):
    """StoreRedis
    """

    def __init__(self, uri: str, **kwargs):
        self._redis = None
        self._new_db('redis://localhost', **kwargs)

    def _new_db(self, uri, param) -> Redis:
        # FIXME : pyredis?
        self._redis: Redis = None   # aioredis.create_redis_pool(uri)
        return self._redis

    def get(self, key: bytes, *, default=None, **kwargs) -> bytes:
        return self._redis.get(key)

    def put(self, key: bytes, value: bytes, *, sync=False, **kwargs):
        return self._redis.set(key, value)

    def delete(self, key: bytes, *, sync=False, **kwargs):
        pass

    def close(self):
        pass

    def destroy_store(self):
        pass

    def write_batch(self, sync=False) -> KeyValueStoreWriteBatch:
        pass

    def cancelable_write_batch(self, sync=False) -> KeyValueStoreCancelableWriteBatch:
        pass

    def iterator(self, start_key: bytes = None, stop_key: bytes = None, include_value: bool = True, **kwargs):
        pass


def _error_convert(func):
    @functools.wraps(func)
    def _wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except RedisError as e:
            raise KeyValueStoreError(e)

    return _wrapper


class _AsyncKeyValueStoreWriteBatchRedis(KeyValueStoreWriteBatch):
    def __init__(self, redis: Redis):
        self._batch = self._new_batch(redis)

    @_error_convert
    def _new_batch(self, redis: Redis):
        return redis.multi_exec()

    @_validate_args_bytes_without_first
    @_error_convert
    def put(self, key: bytes, value: bytes):
        self._batch.set(key, value)

    @_validate_args_bytes_without_first
    @_error_convert
    def delete(self, key: bytes):
        self._batch.delete(key)

    @_error_convert
    def clear(self):
        # FIXME : how to discard?
        pipeline = self._batch._pipeline
        if pipeline:
            for fut, cmd, args, kw in pipeline:
                fut.cancel()
            self._batch._pipeline.clear()

        self._batch._done = True

    @_error_convert
    async def write(self):
        await self._batch.execute()


class _AsyncKeyValueStoreCancelableWriteBatchRedis:
    def __init__(self, store: AsyncKeyValueStore, redis: Redis):
        # super().__init__(store, sync=sync)
        self._touched_keys = set()
        self._redis = redis
        # self._snapshot = db.snapshot()

    def _touch(self, key: bytes):
        self._touched_keys.add(key)

    def _get_original_touched_item(self):
        for key in self._touched_keys:
            try:
                # yield key, self._snapshot.get(key)
                yield key, None
            except KeyError:
                return key, None

    def clear(self):
        # super().clear()
        self._touched_keys.clear()

    def close(self):
        # self._snapshot.close()
        # self._snapshot = None
        pass


class AsyncStoreRedis(AsyncKeyValueStore):
    """AsyncStoreRedis
    """

    def __init__(self, uri: str, **kwargs):
        self._redis = None
        loop = asyncio.get_event_loop()
        loop.create_task(self._new_db(uri, **kwargs))

    async def _new_db(self, uri, **kwargs) -> Redis:
        self._redis: Redis = await aioredis.create_redis_pool(uri)
        print("redis : ", self._redis)
        return self._redis

    async def get(self, key: bytes, *, default=None, **kwargs) -> bytes:
        result = await self._redis.get(key)

        if result is None:
            raise KeyError(f"Has no value of key({key})")
        return result

    async def put(self, key: bytes, value: bytes, *, sync=False, **kwargs) -> bool:
        return await self._redis.set(key, value)

    async def delete(self, key: bytes, *, sync=False, **kwargs):
        pass

    async def close(self):
        self._redis.close()
        await self._redis.wait_closed()

    async def destroy_store(self):
        pass

    async def write_batch(self, sync=False) -> KeyValueStoreWriteBatch:
        return _AsyncKeyValueStoreWriteBatchRedis(self._redis)

    async def cancelable_write_batch(self, sync=False) -> _AsyncKeyValueStoreCancelableWriteBatchRedis:
        # return _AsyncKeyValueStoreCancelableWriteBatchRedis(self, self._redis)
        pass

    async def iterator(self, start_key: bytes = None, stop_key: bytes = None, include_value: bool = True, **kwargs):
        # TODO : need iterator?
        pass
