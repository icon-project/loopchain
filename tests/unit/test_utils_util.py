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
"""Test Utils Util"""

import logging
import unittest
import loopchain.utils as util
import tests.unit.test_util as test_util
from loopchain.utils import loggers

loggers.set_preset_type(loggers.PresetType.develop)
loggers.update_preset()


class TestUtilsUtil(unittest.TestCase):

    def setUp(self):
        test_util.print_testname(self._testMethodName)

    def tearDown(self):
        pass

    def test_parse_target_list(self):
        # GIVEN
        target_a_string = "111.222.333.444:1234"
        targets_string = "111.222.333.444:1234, 100.200.300.400:1000"

        # WHEN
        target_ip_and_port = util.parse_target_list(target_a_string)[0]
        target_list = util.parse_target_list(targets_string)

        # THEN
        self.assertEqual(target_ip_and_port[0], "111.222.333.444")
        self.assertEqual(target_ip_and_port[1], 1234)

        self.assertEqual(target_list[0][0], "111.222.333.444")
        self.assertEqual(target_list[0][1], 1234)

        self.assertEqual(target_list[1][0], "100.200.300.400")
        self.assertEqual(target_list[1][1], 1000)


if __name__ == '__main__':
    unittest.main()
