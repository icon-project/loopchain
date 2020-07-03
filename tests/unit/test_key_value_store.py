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
"""Test KeyValueStore class"""

import unittest

import tests.unit.test_util as test_util
from loopchain import utils
from loopchain.store.key_value_store import KeyValueStoreError, KeyValueStore

utils.loggers.set_preset_type(utils.loggers.PresetType.develop)
utils.loggers.update_preset()


class TestKeyValueStore(unittest.TestCase):

    def setUp(self):
        self.store_types = ['dict', 'plyvel']
        test_util.print_testname(self._testMethodName)

    def tearDown(self):
        pass

    def _get_test_items(self, count: int = 5):
        test_items = dict()
        for i in range(1, count + 1):
            key = bytes(f"test_key_{i}", encoding='utf-8')
            value = bytes(f"test_value_{i}", encoding='utf-8')
            test_items[key] = value
        return test_items

    def _new_store(self, uri, store_type=None, create_if_missing=True):
        try:
            if store_type == KeyValueStore.STORE_TYPE_DICT:
                from loopchain.store.key_value_store_dict import KeyValueStoreDict
                utils.logger.info(f"New KeyValueStore. store_type={store_type}, uri={uri}")
                return KeyValueStoreDict()

            return KeyValueStore.new(uri, store_type=store_type, create_if_missing=create_if_missing)
        except KeyValueStoreError as e:
            utils.logger.spam(f"Doesn't need to clean the store. uri={uri}, e={e}")

        return KeyValueStore.new(uri, store_type=store_type, create_if_missing=True)

    def test_key_value_store_basic(self):
        for store_type in self.store_types:
            test_items = self._get_test_items(5)
            utils.logger.debug(f"test_items={test_items}")

            store = self._new_store("file://./key_value_store_test_basic", store_type=store_type)

            #
            # put/get
            #

            for key, value in test_items.items():
                store.put(key, value)
                self.assertEqual(store.get(key), value)

            with self.assertRaises(KeyError):
                store.get(b'unknown_key')

            self.assertEqual(store.get(b'unknown_key', default=b'test_default_value'), b'test_default_value')

            kwargs = {}

            if store_type is 'dict':
                container = tuple(test_items.keys())
            else:
                kwargs.update({
                    'start_key': b'test_key_2',
                    'stop_key': b'test_key_4'
                })
                container = (b'test_key_2', b'test_key_3', b'test_key_4')
            expect_count = len(container)

            count = 0
            for key, value in store.Iterator(**kwargs):
                self.assertIn(key, container)
                count += 1
            self.assertEqual(count, expect_count)

            if store_type == 'plyvel':
                kwargs.update({'include_stop': True})

            count = 0
            for key, value in store.Iterator(**kwargs):
                self.assertIn(key, container)
                count += 1
            self.assertEqual(count, expect_count)

            count = 0
            if store_type == 'plyvel':
                kwargs.update({'include_stop': False})
                container = (b'test_key_2', b'test_key_3')
                expect_count = 2

            for key, value in store.Iterator(**kwargs):
                self.assertIn(key, container)
                count += 1
            self.assertEqual(count, expect_count)

            #
            # delete
            #

            del_key = b'test_key_2'
            del test_items[del_key]
            store.delete(del_key)
            with self.assertRaises(KeyError):
                store.get(del_key)

            count = 0
            for key, value in store.Iterator():
                utils.logger.spam(f"DB iterator: key={key}, value={value}")
                self.assertEqual(value, test_items[bytes(key)])
                count += 1
            utils.logger.debug(f"Count after {del_key} has been deleted={count}")
            self.assertEqual(count, len(test_items))

            store.destroy_store()

    def test_key_value_store_write_batch(self):
        for store_type in self.store_types:
            store = self._new_store("file://./key_value_store_test_write_batch", store_type=store_type)

            batch = store.WriteBatch()
            batch.put(b'test_key_1', b'test_value_1')
            batch.put(b'test_key_2', b'test_value_2')

            with self.assertRaises(KeyError):
                store.get(b'test_key_1')
            with self.assertRaises(KeyError):
                store.get(b'test_key_2')

            batch.write()
            self.assertEqual(store.get(b'test_key_1'), b'test_value_1')
            self.assertEqual(store.get(b'test_key_2'), b'test_value_2')
            batch = None

            store.destroy_store()

    def test_key_value_store_cancelable_write_batch(self):
        for store_type in self.store_types:
            test_items = self._get_test_items(5)

            store = self._new_store("file://./key_value_store_test_cancelable_write_batch", store_type=store_type)

            for key, value in test_items.items():
                store.put(key, value)

            cancelable_batch = store.CancelableWriteBatch()
            cancelable_batch.put(b'cancelable_key_1', b'cancelable_value_1')
            cancelable_batch.put(b'test_key_2', b'edited_test_value_2')
            cancelable_batch.put(b'cancelable_key_2', b'cancelable_value_2')
            cancelable_batch.put(b'test_key_4', b'edited_test_value_4')
            cancelable_batch.write()

            edited_test_items = test_items.copy()
            edited_test_items[b'cancelable_key_1'] = b'cancelable_value_1'
            edited_test_items[b'test_key_2'] = b'edited_test_value_2'
            edited_test_items[b'cancelable_key_2'] = b'cancelable_value_2'
            edited_test_items[b'test_key_4'] = b'edited_test_value_4'

            count = 0
            for key, value in store.Iterator():
                utils.logger.spam(f"Edited DB iterator: key={key}, value={value}")
                self.assertEqual(value, edited_test_items[bytes(key)])
                count += 1
            utils.logger.debug(f"Count after cancelable_batch has been written={count}")
            self.assertEqual(count, len(edited_test_items))

            cancelable_batch.cancel()
            count = 0
            for key, value in store.Iterator():
                utils.logger.spam(f"Original DB iterator: key={key}, value={value}")
                self.assertEqual(value, test_items[bytes(key)])
                count += 1
            utils.logger.debug(f"Original count={count}")
            self.assertEqual(count, len(test_items))

            cancelable_batch = None

            store.destroy_store()


if __name__ == '__main__':
    unittest.main()
