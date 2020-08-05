from loopchain import configure_default as conf
from loopchain.utils import normalize_request_url


class TestNormalizeRequestURL:
    def test_get_local_endpoint_if_url_input_not_exist(self):
        url_input = None
        expected_result = f"http://127.0.0.1:{conf.PORT_PEER_FOR_REST}/api/v3/{conf.LOOPCHAIN_DEFAULT_CHANNEL}"

        assert expected_result == normalize_request_url(url_input)
