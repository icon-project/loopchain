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

import loopchain.utils as util
import testcase.unittest.test_util as test_util
from loopchain.channel.channel_statemachine import ChannelStateMachine
from loopchain.protos import loopchain_pb2


class MockBlockManager:
    peer_type = loopchain_pb2.BLOCK_GENERATOR

    def __init__(self):
        self.timer_called = 0
        self.peer_type = loopchain_pb2.BLOCK_GENERATOR

    def start_block_generate_timer(self):
        if self.timer_called == 0:
            self.timer_called += 1

    def stop_block_generate_timer(self):
        self.timer_called -= 1


class MockChannelService:
    def __init__(self):
        self.block_manager = MockBlockManager()

    def block_height_sync_channel(self):
        pass

    def evaluate_network(self):
        pass

    def subscribe_network(self):
        pass


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
        self.assertEqual(channel_state_machine.state, "EvaluateNetwork")

    def test_change_state_by_condition(self):
        # GIVEN
        channel_state_machine = ChannelStateMachine(MockChannelService())
        channel_state_machine.complete_init_components()
        channel_state_machine.subscribe_network()
        util.logger.spam(f"\nstate is {channel_state_machine.state}")

        # WHEN
        channel_state_machine.complete_sync()
        util.logger.spam(f"\nstate is {channel_state_machine.state}")

        # THEN
        self.assertEqual(channel_state_machine.state, "BlockGenerate")

    def test_change_state_from_same_state(self):
        # GIVEN
        mock_channel_service = MockChannelService()
        channel_state_machine = ChannelStateMachine(mock_channel_service)
        channel_state_machine.complete_init_components()
        channel_state_machine.subscribe_network()
        channel_state_machine.complete_sync()
        util.logger.spam(f"\nstate is {channel_state_machine.state}")

        # WHEN
        channel_state_machine.turn_to_leader()
        util.logger.spam(f"\ntimer called({mock_channel_service.block_manager.timer_called})")
        channel_state_machine.turn_to_leader()
        util.logger.spam(f"\nstate is {channel_state_machine.state}")

        # THEN
        self.assertEqual(mock_channel_service.block_manager.timer_called, 1)


if __name__ == '__main__':
    unittest.main()
