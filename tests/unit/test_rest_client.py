import os
import pytest
from loopchain.baseservice import RestClient, RestMethod
from loopchain.blockchain.types import Hash32, ExternalAddress
from loopchain.blockchain.transactions import TransactionBuilder, TransactionSerializer, TransactionVersioner
from loopchain.crypto.signature import Signer


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


tv = TransactionVersioner()
tb = TransactionBuilder.new(version="0x2", type_=None, versioner=tv)
tb.signer = Signer.new()
tb.to_address = ExternalAddress(os.urandom(20))
tb.fee = 10
tb.value = 1000
tb.nonce = 123
request_tx2 = tb.build()
request_tx2_param = TransactionSerializer.new("0x2", None, tv).to_raw_data(request_tx2)
request_tx2_param["from_"] = request_tx2_param.pop("from")

tb = TransactionBuilder.new(version="0x3", type_=None, versioner=tv)
tb.step_limit = 1000000
tb.value = 100000
tb.signer = Signer.new()
tb.to_address = ExternalAddress(os.urandom(20))
tb.nid = 3
tb.nonce = 1
tb.data = "test"
tb.data_type = "message"
request_tx3 = tb.build()
request_tx3_param = TransactionSerializer.new("0x3", None, tv).to_raw_data(request_tx3)
request_tx3_param["from_"] = request_tx3_param.pop("from")

request_target = "https://fakewallet.icon.foundation:443"
request_urls = {
    RestMethod.GetChannelInfos: request_target + "/api/node/icon_dex",
    RestMethod.GetBlockByHeight: request_target + "/api/node/icon_dex",
    RestMethod.Status: request_target + "/api/v1/status/peer",
    RestMethod.GetLastBlock: request_target + "/api/v3/icon_dex",
    RestMethod.GetReps: request_target + "/api/v3/icon_dex",
    RestMethod.SendTransaction2: request_target + "/api/v2",
    RestMethod.SendTransaction3: request_target + "/api/v3/icon_dex"
}
request_params = {
    RestMethod.GetChannelInfos: RestMethod.GetChannelInfos.value.params,
    RestMethod.GetBlockByHeight: RestMethod.GetBlockByHeight.value.params("100"),
    RestMethod.Status: RestMethod.Status.value.params,
    RestMethod.GetLastBlock: RestMethod.GetLastBlock.value.params,
    RestMethod.GetReps: RestMethod.GetReps.value.params(Hash32.new().hex_0x()),
    RestMethod.SendTransaction2: RestMethod.SendTransaction2.value.params(**request_tx2_param),
    RestMethod.SendTransaction3: RestMethod.SendTransaction3.value.params(**request_tx3_param)
}
request_tx2_param["from"] = request_tx2_param.pop("from_")
request_tx3_param["from"] = request_tx3_param.pop("from_")
request_params_results = {
    RestMethod.GetChannelInfos: {'jsonrpc': '2.0', 'method': 'node_getChannelInfos'},
    RestMethod.GetBlockByHeight: {'jsonrpc': '2.0', 'method': 'node_getBlockByHeight', 'params': {'height': '100'}},
    RestMethod.Status: {'channel': 'icon_dex'},
    RestMethod.GetLastBlock: {'jsonrpc': '2.0', 'method': 'icx_getLastBlock'},
    RestMethod.GetReps: {'jsonrpc': '2.0', 'method': 'rep_getListByHash', 'params': {'repsHash': Hash32.new().hex_0x()}},
    RestMethod.SendTransaction2: {'jsonrpc': '2.0', 'method': 'icx_sendTransaction', 'params': request_tx2_param},
    RestMethod.SendTransaction3: {'jsonrpc': '2.0', 'method': 'icx_sendTransaction', 'params': request_tx3_param}
}
