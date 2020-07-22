from unittest.mock import MagicMock

import pytest

from loopchain.baseservice.aging_cache import AgingCache
from loopchain.channel.channel_inner_service import ChannelInnerTask
from loopchain.channel.channel_service import ChannelService


@pytest.mark.asyncio
class TestChannelInnerTask:
    # FIXME: dirty mocking

    @pytest.fixture
    def channel_inner_task(self):
        channel_service = MagicMock(ChannelService)
        tx_queue = MagicMock(AgingCache)

        return ChannelInnerTask(
            channel_service,
            tx_queue
        )

    async def test_height_response_updates_height(self, channel_inner_task):
        orig_func = channel_inner_task.block_height_response.__wrapped__

        # GIVEN I got response
        responding_peer = "123.123.123.123:7100"
        responded_height = 100

        # WHEN I triggered to update
        await orig_func(channel_inner_task, responding_peer, responded_height)

        # THEN consensus runner should update the current status
        channel_service = channel_inner_task._channel_service
        channel_service.consensus_runner.update_status.assert_called_with(
            responding_peer, responded_height
        )
