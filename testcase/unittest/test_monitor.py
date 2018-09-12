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
"""Test Process Monitoring Class"""

import unittest

import loopchain.utils as util
from loopchain.baseservice import Monitor
import testcase.unittest.test_util as test_util
from loopchain.utils import loggers


loggers.set_preset_type(loggers.PresetType.develop)
loggers.update_preset()


class TestMonitor(unittest.TestCase):
    def setUp(self):

        test_util.print_testname(self._testMethodName)

    def test_monitor_is_singleton(self):
        # GIVEN
        one = Monitor()
        one_is_run = one.is_run()
        util.logger.spam(f"one is run({one_is_run})")
        one.start()

        # WHEN
        two = Monitor()
        two_is_run = two.is_run()
        util.logger.spam(f"two is run({two_is_run})")

        # THEN
        self.assertTrue(one is two)
        self.assertTrue(one.is_run() and two.is_run() and True)

        # CLEAN
        one.stop()
