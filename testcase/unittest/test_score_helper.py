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
"""Test Score Helper"""
import os
import shutil
import unittest

import os.path as osp

import loopchain.configure as conf
from loopchain.tools.score_helper import ScoreHelper, ScoreDatabaseType
from loopchain.utils import loggers

loggers.set_preset_type(loggers.PresetType.develop)
loggers.update_preset()


class TestScoreHelper(unittest.TestCase):
    conf = None
    __repository_path = osp.join(osp.dirname(__file__), 'db_')

    @classmethod
    def setUpClass(cls):
        conf.DEFAULT_SCORE_REPOSITORY_PATH = cls.__repository_path
        # Deploy path 에 clone 한다
        if osp.exists(cls.__repository_path):
            shutil.rmtree(cls.__repository_path, True)

    @classmethod
    def tearDownClass(cls):
        os.system("rm -rf ./.storage*")

    def test_score_helper_load_databases(self):
        helper = ScoreHelper()
        helper.peer_id = 'test_score_helper_load_databases'
        sqlite_conn = helper.load_database('sqlite_test')
        self.assertIsNotNone(sqlite_conn)
        self.assertIsNotNone(sqlite_conn.cursor())

        leveldb_conn = helper.load_database('leveldb_test', ScoreDatabaseType.leveldb)
        self.assertIsNotNone(leveldb_conn)
        self.assertIsNotNone(sqlite_conn.cursor())


if __name__ == '__main__':
    unittest.main()
