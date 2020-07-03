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

import time
import unittest

import loopchain.utils as util
import tests.unit.test_util as test_util
from loopchain.baseservice.aging_cache import AgingCache
from loopchain.utils import loggers

loggers.set_preset_type(loggers.PresetType.develop)
loggers.update_preset()


class TestAgingCache(unittest.TestCase):

    def setUp(self):
        test_util.print_testname(self._testMethodName)

    def tearDown(self):
        pass

    def test_aging_cache(self):
        # GIVEN
        cache = AgingCache(max_age_seconds=5)
        for i in range(100):
            cache[i] = f"value_{i}"
            # util.logger.spam(f"test_cache cache size({len(cache)}) max_size({cache.maxlen})")
        util.logger.spam(f"test_aging_cache cache size({len(cache)}) max_age_seconds({cache.max_age_seconds})")

        # WHEN
        for i in list(range(100))[-10:]:
            # util.logger.spam(f"({cache[i]})")
            self.assertTrue(i in cache)

        self.assertGreaterEqual(len(cache), 10)
        time.sleep(6)

        # THEN
        cache["aaa"] = "AAA"
        self.assertEqual(len(cache), 1)
        util.logger.spam(f"after test_cache cache size({len(cache)}) max_age_seconds({cache.max_age_seconds})")

    def test_aging_cache_pop(self):
        # GIVEN
        cache = AgingCache(max_age_seconds=5)
        for i in range(10):
            cache[i] = f"value_{i}"
            # util.logger.spam(f"test_cache cache size({len(cache)}) max_size({cache.maxlen})")
        util.logger.spam(f"test_aging_cache_pop cache size({len(cache)}) max_age_seconds({cache.max_age_seconds})")
        self.assertGreaterEqual(len(cache), 10)

        # WHEN
        for i in range(10):
            # util.logger.spam(f"in loop cache({cache}))")
            if i in cache:
                cache.pop(i)

        # THEN
        self.assertEqual(len(cache), 0)

    def test_aging_cache_get(self):
        # GIVEN
        cache = AgingCache(max_age_seconds=5)
        for i in range(10):
            cache[i] = f"value_{i}"
            # util.logger.spam(f"test_cache cache size({len(cache)}) max_size({cache.maxlen})")
        util.logger.spam(f"test_aging_cache_pop cache size({len(cache)}) max_age_seconds({cache.max_age_seconds})")
        self.assertEqual(len(cache), 10)

        expect_none = cache.get(100, None)
        self.assertIsNone(expect_none)

        # WHEN
        for i in range(10):
            if i in cache:
                item = cache[i]
                util.logger.spam(f"in cache item({item})")

        # THEN
        self.assertEqual(len(cache), 10)

    def test_aging_cache_getitem(self):
        # GIVEN
        cache = AgingCache(max_age_seconds=5)
        for i in range(10):
            cache[i] = f"value_{i}"
            # util.logger.spam(f"test_cache cache size({len(cache)}) max_size({cache.maxlen})")
        util.logger.spam(f"test_aging_cache_pop cache size({len(cache)}) max_age_seconds({cache.max_age_seconds})")
        self.assertEqual(len(cache), 10)

        # WHEN
        while cache:
            item = cache.pop_item()
            util.logger.spam(f"in cache item({item})")

        # THEN
        self.assertEqual(len(cache), 0)

    def test_aging_cache_set_get_status(self):
        # GIVEN
        cache = AgingCache(max_age_seconds=5)
        for i in range(10):
            cache[i] = f"value_{i}"
            # util.logger.spam(f"test_cache cache size({len(cache)}) max_size({cache.maxlen})")
        util.logger.spam(f"test_aging_cache_pop cache size({len(cache)}) max_age_seconds({cache.max_age_seconds})")
        self.assertGreaterEqual(len(cache), 10)

        # WHEN
        cache.set_item_status(5, "Some Status")
        for i in range(10):
            item_status = cache.get_item_status(i)
            util.logger.spam(f"in cache item({item_status})")

        # THEN
        self.assertEqual(len(cache), 10)
        self.assertEqual(cache.get_item_status(5), "Some Status")

    def test_aging_cache_set_item_status_by_time(self):
        # GIVEN
        cache = AgingCache(max_age_seconds=5)
        for i in range(10):
            cache[i] = f"value_{i}"
            # util.logger.spam(f"test_cache cache size({len(cache)}) max_size({cache.maxlen})")
        util.logger.spam(f"test_aging_cache_pop cache size({len(cache)}) max_age_seconds({cache.max_age_seconds})")
        self.assertGreaterEqual(len(cache), 10)

        # WHEN
        time.sleep(1)
        cache.set_item_status_by_time(int(time.time()), "timeout")
        for i in range(10, 20):
            cache[i] = f"value_{i}"

        # THEN
        timeout_count = 0
        for i in range(20):
            item_status = cache.get_item_status(i)
            if item_status == "timeout":
                timeout_count += 1
            # util.logger.spam(f"in cache item({item_status})")

        self.assertEqual(timeout_count, 10)

    def test_aging_cache_pop_item_in_status(self):
        # GIVEN
        cache = AgingCache(max_age_seconds=5)
        for i in range(10):
            cache[i] = f"value_{i}"
            # util.logger.spam(f"test_cache cache size({len(cache)}) max_size({cache.maxlen})")
        util.logger.spam(f"test_aging_cache_pop cache size({len(cache)}) max_age_seconds({cache.max_age_seconds})")
        self.assertGreaterEqual(len(cache), 10)

        # WHEN
        cache.set_item_status(5, "Some Status")
        item_count = 0
        for i in range(10):
            item = cache.pop_item_in_status()
            if item:
                item_count += 1

        # THEN
        self.assertEqual(item_count, 9)

    def test_aging_cache_get_item_in_status(self):
        # GIVEN
        cache = AgingCache(max_age_seconds=5)
        for i in range(10):
            cache[i] = f"value_{i}"
            # util.logger.spam(f"test_cache cache size({len(cache)}) max_size({cache.maxlen})")
        util.logger.spam(f"test_aging_cache_pop cache size({len(cache)}) max_age_seconds({cache.max_age_seconds})")
        self.assertGreaterEqual(len(cache), 10)

        # WHEN
        for i in range(10):
            item = cache.get_item_in_status(AgingCache.DEFAULT_ITEM_STATUS, "Some Status")
            util.logger.spam(f"item({item})")

        # THEN
        item_count = 0
        for i in range(10):
            item = cache.get_item_in_status(AgingCache.DEFAULT_ITEM_STATUS, "Some Status")
            if item:
                item_count += 1

        self.assertEqual(len(cache), 10)
        self.assertEqual(item_count, 0)


if __name__ == '__main__':
    unittest.main()
