import urllib

import aioredis
from aioredis import Redis

from loopchain.store.key_value_store import (
    KeyValueStore,
    KeyValueStoreCancelableWriteBatch,
    KeyValueStoreWriteBatch,
    AsyncKeyValueStore
)


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



