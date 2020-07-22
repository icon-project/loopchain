import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Callable
from unittest.mock import MagicMock

import pytest

from loopchain import PeerService
from loopchain.baseservice import ObjectManager
from loopchain.channel.channel_inner_service import ChannelInnerStub, ChannelInnerTask
from loopchain.peer import PeerOuterService
from loopchain.protos import (
    HeightRequest, PeerHeight
)
from loopchain.utils.message_queue import StubCollection

CHANNEL_NAME = "test_channel"


@pytest.fixture
def mocking_object_manager():
    peer_service = MagicMock(PeerService)
    peer_service.inner_service.loop = asyncio.get_event_loop()

    ObjectManager().peer_service = peer_service

    yield

    ObjectManager().peer_service = None


@pytest.fixture
def outer_service(mocking_object_manager):
    return PeerOuterService()


@pytest.fixture(autouse=True)
def stub_collection():
    orig_channel_stubs = StubCollection().channel_stubs

    channel_stub = MagicMock(ChannelInnerStub)
    channel_inner_task = MagicMock(ChannelInnerTask)
    channel_stub.async_task.return_value = channel_inner_task

    channel_stubs = {
        CHANNEL_NAME: channel_stub
    }

    StubCollection().channel_stubs = channel_stubs

    yield

    StubCollection().channel_stubs = orig_channel_stubs


@pytest.fixture
def get_inner_task_checker() -> Callable[...,  MagicMock]:
    def _mock_inner_task_func(func_name) -> MagicMock:
        checker = MagicMock()

        async def target_coro_double(*args, **kwargs):
            return checker(*args, **kwargs)

        channel_stub = StubCollection().channel_stubs[CHANNEL_NAME]
        inner_task = channel_stub.async_task()
        setattr(inner_task, func_name, target_coro_double)

        return checker

    return _mock_inner_task_func


@pytest.mark.asyncio
class TestHeightCommunication:
    async def test_trigger_height_response_after_height_requested(self, outer_service, get_inner_task_checker):
        # GIVEN Nothing is requested
        checker = get_inner_task_checker("block_height_request")
        assert not checker.call_count

        # WHEN The node is requested BlockHeightRequest
        with ThreadPoolExecutor() as executor:
            req_type = HeightRequest(channel=CHANNEL_NAME)
            executor.submit(outer_service.BlockHeightRequest, req_type, "context")
            await asyncio.sleep(.5)

        # THEN The node triggers correspond func
        assert checker.call_count == 1

    async def test_trigger_height_update_after_height_responded(self, outer_service, get_inner_task_checker):
        # GIVEN Nothing is responded
        checker = get_inner_task_checker("block_height_response")
        assert not checker.call_count

        # WHEN The node got response against BlockHeightRequest
        with ThreadPoolExecutor() as executor:
            req_type = PeerHeight(channel=CHANNEL_NAME)
            executor.submit(outer_service.BlockHeightResponse, req_type, "context")
            await asyncio.sleep(.5)

        # THEN The node triggers correspond func
        assert checker.call_count == 1
