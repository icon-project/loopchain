import pytest
from loopchain.baseservice import RestClient, RestMethod
from loopchain.blockchain.types import Hash32


class TestRestClient:
    @pytest.fixture
    def rest_client(self):
        client = RestClient()
        client._target = request_target
        return client

    @pytest.mark.parametrize("rest_method", RestMethod)
    def test_url(self, rest_client: RestClient, rest_method: RestMethod):
        url = rest_client.create_url(rest_client._target, rest_method)
        assert url == request_urls[rest_method]

    @pytest.mark.parametrize("rest_method", RestMethod)
    def test_params(self, rest_client: RestClient, rest_method: RestMethod):
        params = rest_client.create_params(rest_method, request_params[rest_method])
        params.pop('id', None)
        assert params == request_params_results[rest_method]


request_target = "https://fakewallet.icon.foundation:443"
request_urls = {
    RestMethod.GetChannelInfos: request_target + "/api/node/icon_dex",
    RestMethod.GetBlockByHeight: request_target + "/api/node/icon_dex",
    RestMethod.Status: request_target + "/api/v1/status/peer",
    RestMethod.GetLastBlock: request_target + "/api/v3/icon_dex",
    RestMethod.GetReps: request_target + "/api/v3/icon_dex"
}
request_params = {
    RestMethod.GetChannelInfos: RestMethod.GetChannelInfos.value.params,
    RestMethod.GetBlockByHeight: RestMethod.GetBlockByHeight.value.params("100"),
    RestMethod.Status: RestMethod.Status.value.params,
    RestMethod.GetLastBlock: RestMethod.GetLastBlock.value.params,
    RestMethod.GetReps: RestMethod.GetReps.value.params(Hash32.new().hex_0x())
}
request_params_results = {
    RestMethod.GetChannelInfos: {'jsonrpc': '2.0', 'method': 'node_getChannelInfos'},
    RestMethod.GetBlockByHeight: {'jsonrpc': '2.0', 'method': 'node_getBlockByHeight', 'params': {'height': '100'}},
    RestMethod.Status: {'channel': 'icon_dex'},
    RestMethod.GetLastBlock: {'jsonrpc': '2.0', 'method': 'icx_getLastBlock'},
    RestMethod.GetReps: {'jsonrpc': '2.0', 'method': 'rep_getListByHash', 'params': {'repsHash': Hash32.new().hex_0x()}}
}
