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
"""Test Channel Manager for new functions not duplicated another tests"""
import unittest

import loopchain.utils as util
import testcase.unittest.test_util as test_util
from loopchain.channel.channel_statemachine import ChannelStateMachine


class TestChannelStateMachine(unittest.TestCase):

    def setUp(self):
        test_util.print_testname(self._testMethodName)

    def tearDown(self):
        pass

    def test_init_channel_state(self):
        # GIVEN
        channel_state_machine = ChannelStateMachine()
        util.logger.spam(f"\nstate is {channel_state_machine.state}")

        # WHEN
        channel_state_machine.complete_init_components()
        util.logger.spam(f"\nstate is {channel_state_machine.state}")

        # THEN
        self.assertEqual(channel_state_machine.state, "BlockSync")


if __name__ == '__main__':
    unittest.main()
