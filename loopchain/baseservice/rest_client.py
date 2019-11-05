"""The Client Interface for REST call."""

from collections import namedtuple
from enum import Enum
from typing import Optional, NamedTuple

import requests
from aiohttp import ClientSession
from jsonrpcclient import HTTPClient, Request
from jsonrpcclient.aiohttp_client import aiohttpClient

from loopchain import utils, configure as conf

_RestMethod = namedtuple("_RestMethod", "version name params")


class RestMethod(Enum):
    GetChannelInfos = _RestMethod(conf.ApiVersion.node, "node_getChannelInfos", None)
    GetBlockByHeight = _RestMethod(conf.ApiVersion.node, "node_getBlockByHeight", namedtuple("Params", "height"))
    Status = _RestMethod(conf.ApiVersion.v1, "/status/peer", None)
    GetLastBlock = _RestMethod(conf.ApiVersion.v3, "icx_getLastBlock", None)
    GetReps = _RestMethod(conf.ApiVersion.v3, "rep_getListByHash", namedtuple("Params", "repsHash"))
    SendTransaction2 = _RestMethod(conf.ApiVersion.v2, "icx_sendTransaction",
                                   namedtuple("Params", "from_ to value fee timestamp nonce tx_hash signature"))
    SendTransaction3 = _RestMethod(conf.ApiVersion.v3, "icx_sendTransaction",
                                   namedtuple("Params",
                                              ("from_", "to", "version", "stepLimit", "timestamp", "nid", "signature",
                                               "dataType", "data", "value", "nonce"),
                                              defaults=(None, None, None, None)))


class RestClient:
    def __init__(self, channel=None):
        self._channel_name = channel or conf.LOOPCHAIN_DEFAULT_CHANNEL

    def call(self, uri, method: RestMethod, params: Optional[NamedTuple] = None, timeout=None) -> dict:
        timeout = timeout or conf.REST_ADDITIONAL_TIMEOUT

        try:
            if method.value.version == conf.ApiVersion.v1:
                response = self._call_rest(uri, method, timeout)
            else:
                response = self._call_jsonrpc(uri, method, params, timeout)
        except Exception as e:
            raise
        else:
            utils.logger.spam(f"REST call complete method_name({method.value.name})")
            return response

    async def call_async(self, uri, method: RestMethod, params: Optional[NamedTuple] = None, timeout=None) -> dict:
        timeout = timeout or conf.REST_ADDITIONAL_TIMEOUT

        try:
            if method.value.version == conf.ApiVersion.v1:
                response = await self._call_async_rest(uri, method, timeout)
            else:
                response = await self._call_async_jsonrpc(uri, method, params, timeout)
        except Exception as e:
            raise
        else:
            utils.logger.spam(f"REST call async complete with uri({uri}) method_name({method.value.name})")
            return response

    def _call_rest(self, target: str, method: RestMethod, timeout):
        url = self._create_rest_url(target, method)
        params = self._create_rest_params()
        response = requests.get(url=url,
                                params=params,
                                timeout=timeout)
        if response.status_code != 200:
            raise ConnectionError
        return response.json()

    def _call_jsonrpc(self, target: str, method: RestMethod, params: Optional[NamedTuple], timeout):
        url = self._create_jsonrpc_url(target, method)
        http_client = HTTPClient(url)
        request = self._create_jsonrpc_params(method, params)
        return http_client.send(request, timeout=timeout)

    async def _call_async_rest(self, target: str, method: RestMethod, timeout):
        url = self._create_rest_url(target, method)
        params = self._create_rest_params()
        async with ClientSession() as session:
            async with session.get(url=url,
                                   params=params,
                                   timeout=timeout) as response:
                return await response.json()

    async def _call_async_jsonrpc(self, target: str, method: RestMethod, params: Optional[NamedTuple], timeout):
        # 'aioHttpClient' does not support 'timeout'
        url = self._create_jsonrpc_url(target, method)
        async with ClientSession() as session:
            http_client = aiohttpClient(session, url)
            request = self._create_jsonrpc_params(method, params)
            return await http_client.send(request)

    def create_url(self, target: str, method: RestMethod):
        if method.value.version == conf.ApiVersion.v1:
            return self._create_rest_url(target, method)
        else:
            return self._create_jsonrpc_url(target, method)

    def _create_rest_url(self, target: str, method: RestMethod):
        url = utils.normalize_request_url(target, method.value.version, self._channel_name)
        url += method.value.name
        return url

    def _create_jsonrpc_url(self, target: str, method: RestMethod):
        return utils.normalize_request_url(target, method.value.version, self._channel_name)

    def create_params(self, method: RestMethod, params: Optional[NamedTuple]):
        if method.value.version == conf.ApiVersion.v1:
            return self._create_rest_params()
        else:
            return self._create_jsonrpc_params(method, params)

    def _create_rest_params(self):
        return {
            "channel": self._channel_name
        }

    def _create_jsonrpc_params(self, method: RestMethod, params: Optional[NamedTuple]):
        # 'vars(namedtuple)' does not working in Python 3.7.4
        # noinspection PyProtectedMember
        params = params._asdict() if params else None
        if params:
            params = {k: v for k, v in params.items() if v is not None}
            if "from_" in params:
                params["from"] = params.pop("from_")

        return Request(method.value.name, params) if params else Request(method.value.name)

