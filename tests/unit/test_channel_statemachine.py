#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2018 ICON Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import unittest
from unittest.mock import MagicMock

import loopchain.utils as util
import tests.unit.test_util as test_util
from loopchain.blockchain.blockchain import BlockChain
from loopchain.channel.channel_statemachine import ChannelStateMachine
from loopchain.protos import loopchain_pb2


class MockBlockManager:
    def __init__(self):
        self.timer_called = 0
        self.peer_type = loopchain_pb2.BLOCK_GENERATOR
        self.blockchain = MagicMock(BlockChain)

    def start_block_generate_timer(self):
        if self.timer_called == 0:
            self.timer_called += 1

    def stop_block_generate_timer(self):
        self.timer_called -= 1

    def block_height_sync(self):
        pass

    def stop_block_height_sync_timer(self):
        pass

    def update_service_status(self, status):
        pass

    def start_epoch(self):
        pass

    async def relay_all_txs(self):
        pass


class MockPeerManager:
    def update_all_peers(self):
        pass


class MockBlockManagerCitizen(MockBlockManager):
    def __init__(self):
        super().__init__()
        self.peer_type = loopchain_pb2.PEER


class MockInnerService:
    def notify_unregister(self):
        pass


class MockChannelService:
    def __init__(self):
        self.block_manager = MockBlockManager()
        self.peer_manager = MockPeerManager()
        self.inner_service = MockInnerService()

    async def evaluate_network(self):
        pass

    async def subscribe_network(self):
        pass

    def update_nid(self):
        pass

    def start_subscribe_timer(self):
        pass

    def start_shutdown_timer_when_fail_subscribe(self):
        pass

    def stop_subscribe_timer(self):
        pass

    def stop_shutdown_timer_when_fail_subscribe(self):
        pass

    def is_support_node_function(self, _):
        return True

    def start_block_monitoring_timer(self):
        pass

    def stop_block_monitoring_timer(self):
        pass


class MockChannelServiceCitizen(MockChannelService):
    def __init__(self):
        super().__init__()
        self.block_manager = MockBlockManagerCitizen()

    def is_support_node_function(self, node_function):
        return False


class TestChannelStateMachine(unittest.TestCase):

    def setUp(self):
        test_util.print_testname(self._testMethodName)

    def tearDown(self):
        pass

    def test_init_channel_state(self):
        # GIVEN
        channel_state_machine = ChannelStateMachine(MockChannelService())
        util.logger.spam(f"\nstate is {channel_state_machine.state}")

        # WHEN
        channel_state_machine.complete_init_components()
        util.logger.spam(f"\nstate is {channel_state_machine.state}")

        # THEN
        self.assertEqual("EvaluateNetwork", channel_state_machine.state)

    def test_change_state_by_condition(self):
        # GIVEN
        channel_state_machine = ChannelStateMachine(MockChannelService())
        channel_state_machine.complete_init_components()
        channel_state_machine.block_sync()
        channel_state_machine.complete_sync()
        util.logger.spam(f"\nstate is {channel_state_machine.state}")

        # WHEN
        channel_state_machine.complete_subscribe()
        util.logger.spam(f"\nstate is {channel_state_machine.state}")

        # THEN
        self.assertEqual("BlockGenerate", channel_state_machine.state)

    def test_change_state_by_multiple_condition(self):
        # GIVEN
        channel_state_machine = ChannelStateMachine(MockChannelServiceCitizen())
        channel_state_machine.complete_init_components()
        channel_state_machine.block_sync()
        channel_state_machine.complete_sync()
        util.logger.spam(f"\nstate is {channel_state_machine.state}")

        # WHEN
        channel_state_machine.complete_subscribe()
        util.logger.spam(f"\nstate is {channel_state_machine.state}")

        # THEN
        self.assertEqual("Watch", channel_state_machine.state)

    def test_change_state_from_same_state(self):
        # GIVEN
        mock_channel_service = MockChannelService()
        channel_state_machine = ChannelStateMachine(mock_channel_service)
        channel_state_machine.complete_init_components()
        channel_state_machine.block_sync()
        channel_state_machine.complete_sync()
        channel_state_machine.complete_subscribe()
        util.logger.spam(f"\nstate is {channel_state_machine.state}")

        # WHEN
        channel_state_machine.turn_to_leader()
        util.logger.spam(f"\ntimer called({mock_channel_service.block_manager.timer_called})")
        channel_state_machine.turn_to_leader()
        util.logger.spam(f"\nstate is {channel_state_machine.state}")

        # THEN
        self.assertEqual(1, mock_channel_service.block_manager.timer_called)


if __name__ == '__main__':
    unittest.main()
