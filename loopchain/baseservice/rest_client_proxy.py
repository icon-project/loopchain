"""A proxy class for REST call."""

from typing import Optional, NamedTuple

from loopchain.baseservice import RestClient, RestMethod, NodePool


class RestClientProxy:
    def __init__(self, channel):
        self.node_pool = NodePool(channel)
        self.rest_client = RestClient(channel)

    def call(self, method: RestMethod, params: Optional[NamedTuple] = None, timeout=None) -> dict:
        uri = self.node_pool.target
        try:
            return self.rest_client.call(uri, method, params, timeout)
        except Exception:
            self.node_pool.find_next()
            raise

    async def call_async(self, method: RestMethod, params: Optional[NamedTuple] = None, timeout=None) -> dict:
        uri = self.node_pool.target
        try:
            return await self.rest_client.call_async(uri, method, params, timeout)
        except Exception:
            self.node_pool.find_next()
            raise
