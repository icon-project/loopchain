#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2019 ICON Foundation
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
"""Test lru_cache"""

import timeit
import unittest
from functools import lru_cache
from functools import partial

import loopchain.utils as util
import tests.unit.test_util as test_util
from loopchain.utils import loggers

loggers.set_preset_type(loggers.PresetType.develop)
loggers.update_preset()


class TestLruCache(unittest.TestCase):

    def setUp(self):
        test_util.print_testname(self._testMethodName)

    def tearDown(self):
        pass

    def get_big_list_without_cache(self, size):
        ret = []
        for i in range(size):
            ret.append(i ** i)
        return ret

    @lru_cache(maxsize=4)
    def get_big_list_with_cache(self, size):
        ret = []
        for i in range(size):
            ret.append(i ** i)
        return ret

    def test_lru_cache(self):
        # GIVEN
        test_number = 100
        func_without_cache = partial(self.get_big_list_without_cache, test_number)
        func_with_cache = partial(self.get_big_list_with_cache, test_number)

        # WHEN
        without_cache = timeit.timeit(func_without_cache, number=test_number)
        with_cache = timeit.timeit(func_with_cache, number=test_number)
        util.logger.debug(f"timeit with cache({with_cache}), without cache({without_cache})")

        # THEN
        self.assertGreater(without_cache, with_cache)

    def test_lru_cache_use_returns_as_immutable(self):
        # GIVEN
        returns_origin = self.get_big_list_with_cache(10)

        # (Notice!) You must copy it before changing the value returned by lru_cache.
        returns = self.get_big_list_with_cache(10).copy()

        # WHEN
        returns.pop(0)
        returns2 = self.get_big_list_with_cache(10)

        # THEN
        util.logger.debug(f"returns_origin({returns_origin}), returns({returns}), returns2({returns2})")
        self.assertNotEqual(returns, returns2)
        self.assertEqual(returns2, returns_origin)

    def test_cache_clear(self):
        from unittest.mock import MagicMock
        call_check_mock = MagicMock()

        @lru_cache(maxsize=4)
        def target_func():
            call_check_mock()

        target_func()
        self.assertEqual(call_check_mock.call_count, 1)
        target_func()
        self.assertEqual(call_check_mock.call_count, 1)


        # WHEN
        target_func.cache_clear()
        target_func()
        self.assertEqual(call_check_mock.call_count, 2)


if __name__ == '__main__':
    unittest.main()
