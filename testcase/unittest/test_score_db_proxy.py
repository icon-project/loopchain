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
"""Test Score DB Proxy"""

import logging
import shutil
import unittest

import leveldb

import testcase.unittest.test_util as test_util
from loopchain import configure as conf
from loopchain.tools.score_helper.score_db_proxy import ScoreDbProxy
from loopchain.utils import loggers

loggers.set_preset_type(loggers.PresetType.develop)
loggers.update_preset()


class MockGenesisBlock:
    height = 0
    block_hash = "genesis_block"
    prev_block_hash = ""


class MockBlock:
    height = 1
    block_hash = "next_block"
    prev_block_hash = MockGenesisBlock.block_hash


class TestDbProxy(unittest.TestCase):
    db_path = conf.LOOPCHAIN_ROOT_PATH + "/testcase/unittest/score_db_sample"
    put_items = {b"a": b"a", b"b": b"b", b"c": b"c"}

    def setUp(self):
        test_util.print_testname(f"{self._testMethodName} \n {self._testMethodDoc}")
        self.db_connection = leveldb.LevelDB(self.db_path, create_if_missing=True)
        self.db_proxy = ScoreDbProxy(self.db_connection)
        self.db_proxy.init_invoke(MockGenesisBlock())

    def tearDown(self):
        # delete db and db link objects
        del self.db_proxy._ScoreDbProxy__db_connection
        del self.db_connection
        shutil.rmtree(self.db_path)

    def test_block_commit(self):
        """ GIVEN db_proxy, put multiple data, leveldb can't find  multiple data
        WHEN db_proxy.tx_commit (still leveldb can't find multiple data), db_proxy.block_commit
        THEN leveldb can find multiple data
        """
        # GIVEN
        self.__put_items_to_db_proxy()

        # check from db
        self.__verify_items_not_exist_in_leveldb(self.put_items)
        self.__verify_items_in_db_proxy()

        # WHEN
        self.db_proxy.commit_tx()
        self.assertDictEqual({}, self.db_proxy._ScoreDbProxy__tx_apply_state)
        self.__verify_items_not_exist_in_leveldb(self.put_items)
        self.__verify_items_in_db_proxy()
        self.db_proxy.precommit_block()
        self.assertDictEqual(self.put_items, self.db_proxy
                             ._ScoreDbProxy__precommit_state[MockGenesisBlock.height][MockGenesisBlock.block_hash])
        self.__verify_items_not_exist_in_leveldb(self.put_items)
        self.db_proxy.init_invoke(MockBlock())
        self.__verify_items_in_db_proxy()
        self.db_proxy.commit_block(MockGenesisBlock.height, MockGenesisBlock.block_hash)  # must remove precommited genesis_state
        with self.assertRaises(KeyError):
            self.db_proxy._ScoreDbProxy__precommit_state[MockGenesisBlock.height]

        # THEN
        self.__verify_items_in_db_proxy()
        self.assertDictEqual({}, self.db_proxy._ScoreDbProxy__block_apply_state)
        self.assertDictEqual({}, self.db_proxy._ScoreDbProxy__tx_apply_state)
        self.__verify_items_in_db_connection()

    def test_put_invalid_item(self):
        """ GIVEN invalid_items(not byte) to db_proxy
        WHEN commit_block
        THEN db_proxy must rollback all items
        """
        self.__put_items_to_db_proxy()
        self.__commit_db_proxy_state()

        invalid_items = {b"a": "a", b"b": "b"}
        self.db_proxy._ScoreDbProxy__block_apply_state = invalid_items
        self.db_proxy.precommit_block()
        self.db_proxy.commit_block(MockGenesisBlock.height, MockGenesisBlock.block_hash)

        # verify rollback
        self.__verify_items_in_db_proxy()
        self.__verify_items_in_db_connection()

    def test_rollback_db(self):
        self.__put_items_to_db_proxy()
        self.__commit_db_proxy_state()

        self.db_proxy._ScoreDbProxy__now_block_height = MockBlock.height
        self.db_proxy._ScoreDbProxy__now_block_hash = MockBlock.block_hash

        self.db_proxy.Put(b"a", b"b")
        self.db_proxy.Put(b"b", b"c")

        self.db_proxy.commit_tx()
        self.db_proxy.precommit_block()
        self.db_proxy.commit_block(MockBlock.height, MockBlock.block_hash)

        self.assertEqual(self.db_connection.Get(b"a"), b"b")
        self.assertEqual(self.db_connection.Get(b"b"), b"c")

        self.db_proxy.rollback_db()
        self.__verify_items_in_db_proxy()
        self.__verify_items_in_db_connection()

    def __commit_db_proxy_state(self):
        self.db_proxy.commit_tx()
        self.db_proxy.precommit_block()
        self.db_proxy.commit_block(MockGenesisBlock.height, MockGenesisBlock.block_hash)
        self.db_proxy.reset_backup()

    def __verify_items_in_db_connection(self):
        for key, value in self.put_items.items():
            self.assertEqual(self.db_connection.Get(key), value)

    def __verify_items_in_db_proxy(self):
        for key, value in self.put_items.items():
            self.assertEqual(self.db_proxy.Get(key), value)

    def __put_items_to_db_proxy(self):
        for key, value in self.put_items.items():
            self.db_proxy.Put(key, value)

    def __verify_items_not_exist_in_leveldb(self, put_items):
        for key in put_items.keys():
            with self.assertRaises(KeyError):
                self.db_connection.Get(key)

    def __verify_items_not_exist_in_db_proxy(self):
        for key in self.put_items.keys():
            with self.assertRaises(KeyError):
                self.db_proxy.Get(key)
