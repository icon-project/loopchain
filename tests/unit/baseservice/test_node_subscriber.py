import asyncio
import json
import urllib

import pytest
import websockets

from loopchain.baseservice import ObjectManager
from loopchain.baseservice.node_subscriber import (NodeSubscriber, _check_error_in_response,
                                                   CONNECTION_FAIL_CONDITIONS, UnregisteredException)
from loopchain.protos import message_code

from loopchain.blockchain import AnnounceNewBlockError


def get_response_dict(code=message_code.Response.success):
    return {
        "jsonrpc": "2.0",
        "method": "node_ws_PublishAnything",
        "params": {
            "error": "test",
            "code": code
        },
        "id": 1234
    }


@pytest.fixture
def mock_ws(mocker):
    class MockWebSocket:
        def __init__(self, mocker_fixture):
            self.mock_send = mocker_fixture.MagicMock()
            msg_from_rs = json.dumps({"test": "success message from rs_target!"})
            self.mock_recv = mocker_fixture.MagicMock(return_value=msg_from_rs)
            self.mock_close = mocker_fixture.MagicMock()

        @property
        def closed(self) -> bool:
            """Fake status for websocket connection.

            When initialized, returns True (Connection not established).
            When any of send or recv is called (for faking handshake steps), returns True (Connection established).
            When close is called, returns True (Connnection closed).
            """
            is_sent = self.mock_send.called
            is_recv = self.mock_send.called
            is_closed = self.mock_close.called

            if is_closed:
                return True
            if is_sent or is_recv:
                return False
            else:
                return True

        async def send(self, request):
            self.mock_send()

            return True

        async def recv(self):
            returned_value = self.mock_recv()
            return returned_value

        async def close(self):
            self.mock_close()
            return True

    return MockWebSocket(mocker)


@pytest.fixture
def node_subscriber():
    channel = "channel"
    rs_target = "https://test.com"

    return NodeSubscriber(channel, rs_target)


class TestHelper:
    @pytest.mark.parametrize("code", CONNECTION_FAIL_CONDITIONS)
    def test_acceptable_errors_in_response(self, code):
        response_dict = get_response_dict(code)
        with pytest.raises(UnregisteredException):
            _check_error_in_response(response_dict)

    @pytest.mark.parametrize("code", [
        message_code.Response.fail
    ])
    def test_critical_errors_in_in_response(self, code):
        response_dict = get_response_dict(code)
        with pytest.raises(AnnounceNewBlockError):
            _check_error_in_response(response_dict)

    @pytest.mark.parametrize("rs_target, expected_scheme", [
        ("https://test.com", "wss"),
        ("http://test.com", "ws"),
        ("fake-scheme://test.com", "ws"),
    ])
    def test_target_uri_has_valid_websocket_scheme(self, rs_target, expected_scheme):
        channel = "channel"
        node_subscriber = NodeSubscriber(channel, rs_target)

        target_uri = node_subscriber._target_uri
        scheme = urllib.parse.urlparse(target_uri).scheme

        assert scheme == expected_scheme


@pytest.mark.asyncio
class TestNodeSubscriberBasic:
    async def test_init_connection(self, node_subscriber, monkeypatch, mock_ws):
        async def mock_connect(*args, **kwargs):
            return mock_ws
        node_subscriber._websocket = "a"

        with monkeypatch.context() as m:
            m.setattr(websockets, "connect", mock_connect)
            await node_subscriber._prepare_connection()

        assert node_subscriber._websocket == mock_ws

    @pytest.mark.parametrize("code", [
        message_code.Response.fail_subscribe_limit
    ])
    async def test_response_msg_contains_error(self, node_subscriber, mock_ws, code):
        response_dict = get_response_dict(code)
        mock_ws.mock_recv.return_value = json.dumps(response_dict)
        node_subscriber._websocket = mock_ws
        node_subscriber._subscribe_event = asyncio.Event()

        with pytest.raises(UnregisteredException):
            await node_subscriber._recv_until_timeout()


@pytest.mark.asyncio
class TestNodeSubscriberHandShake:
    async def test_handshake_success(self, node_subscriber, mock_ws):
        node_subscriber._websocket = mock_ws
        node_subscriber._subscribe_event = asyncio.Event()
        assert mock_ws.closed

        await node_subscriber._handshake(block_height=1)
        assert mock_ws.mock_send.called
        assert mock_ws.mock_recv.called
        assert not mock_ws.closed

    async def test_handshake_failure_in_request_ensures_ws_close(self, node_subscriber, mock_ws):
        mock_ws.mock_send.side_effect = ConnectionError("Handshake error in send!")
        node_subscriber._websocket = mock_ws
        assert mock_ws.closed

        with pytest.raises(ConnectionError):
            await node_subscriber._handshake(block_height=1)

        assert mock_ws.closed

    async def test_handshake_failure_in_response_ensures_ws_close(self, node_subscriber, mock_ws):
        mock_ws.mock_recv.side_effect = ConnectionError("Handshake error in recv!")
        node_subscriber._websocket = mock_ws
        assert mock_ws.closed

        with pytest.raises(ConnectionError):
            await node_subscriber._handshake(block_height=1)

        assert mock_ws.closed

    @pytest.mark.parametrize("code", CONNECTION_FAIL_CONDITIONS)
    async def test_handshake_failure_by_returned_conn_fail_msgs_ensures_ws_close(self, node_subscriber, mock_ws, code):
        response_dict = get_response_dict(code)
        mock_ws.mock_recv.return_value = json.dumps(response_dict)
        node_subscriber._websocket = mock_ws
        assert mock_ws.closed

        with pytest.raises(UnregisteredException):
            await node_subscriber._handshake(block_height=1)

        assert mock_ws.closed


@pytest.mark.asyncio
class TestNodeSubscriberFunctional:
    @pytest.mark.parametrize("to_be_raised_exc, expected_exc", [
        (AnnounceNewBlockError, AnnounceNewBlockError),
        (RuntimeError, ConnectionError)
    ])
    async def test_subscribe_loop_failure_ensures_ws_close(self, node_subscriber, mock_ws,
                                                           to_be_raised_exc, expected_exc):
        async def mock_recv_until_timeout(*args, **kwargs):
            raise to_be_raised_exc

        node_subscriber._websocket = mock_ws
        mock_ws.mock_send()
        mock_ws.mock_recv()
        assert not mock_ws.closed

        node_subscriber._recv_until_timeout = mock_recv_until_timeout
        with pytest.raises(expected_exc):
            await node_subscriber._run()

        assert mock_ws.closed

    @pytest.mark.skip(reason="...")
    async def test_node_ws_PublishNewBlock(self):
        pass

    @pytest.mark.skip(reason="Tested in TimerService")
    async def test_node_ws_PublishHeartbeat(self):
        pass
