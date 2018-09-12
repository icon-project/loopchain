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
from loopchain.baseservice.cache import Cache
from loopchain.utils import loggers

loggers.set_preset_type(loggers.PresetType.develop)
loggers.update_preset()


class TestCache(unittest.TestCase):

    def setUp(self):
        test_util.print_testname(self._testMethodName)

    def tearDown(self):
        pass

    def test_cache(self):
        # GIVEN
        cache = Cache(maxlen=10)
        util.logger.spam(f"test_cache cache size({len(cache)}) max_size({cache.maxlen})")

        # WHEN
        for i in range(100):
            cache[i] = f"value_{i}"
            # util.logger.spam(f"test_cache cache size({len(cache)}) max_size({cache.maxlen})")

        # THEN
        for i in list(range(100))[-10:]:
            # util.logger.spam(f"({cache[i]})")
            self.assertTrue(i in cache)

        # util.logger.spam(f"({cache[1]})")  # KeyError is correct result.

        self.assertEqual(10, len(cache))


if __name__ == '__main__':
    unittest.main()
