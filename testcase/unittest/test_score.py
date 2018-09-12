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
"""Test Score Invoke and Query"""

import leveldb
import logging
import sqlite3
import unittest

import testcase.unittest.test_util as test_util
from loopchain import configure as conf
from loopchain.blockchain import BlockChain, BlockStatus, Block
from loopchain.blockchain import ScoreBase
from loopchain.utils import loggers
from testcase.unittest.mock_peer import set_mock


loggers.set_preset_type(loggers.PresetType.develop)
loggers.update_preset()


class TestScore(unittest.TestCase):
    chain = None
    test_block_db = 'test_chain_code_block'
    score = None
    __peer_id = 'aaa'

    @classmethod
    def setUpClass(cls):
        """
        블럭체인 생성 및 DB입력
        """
        cls.__peer_auth = test_util.create_default_peer_auth()
        cls.__peer_auth = test_util.create_default_peer_auth()

        set_mock(cls)
        # BlockChain 을 만듬
        test_db = leveldb.LevelDB('./' + cls.test_block_db, create_if_missing=True)
        cls.assertIsNotNone(test_db, "DB생성 불가")
        cls.chain = BlockChain(test_db)
        cls.score = cls.SampleScore()

    def setUp(self):
        test_util.print_testname(self._testMethodName)

    @classmethod
    def tearDownClass(cls):
        """
        테스트로 생성한 블럭체인 디비 제거
        """
        leveldb.DestroyDB(cls.test_block_db)

    def generate_block(self):
        """임시 블럭 생성하는 메소드

        :return: 임시 블럭
        """
        block = Block(channel_name=conf.LOOPCHAIN_DEFAULT_CHANNEL)
        for x in range(10):
            tx = test_util.create_basic_tx(self.__peer_id, self.__peer_auth)
            block.put_transaction(tx)
        block.generate_block(self.chain.last_block)
        return block

    class SampleScore(ScoreBase):
        """ 체인코드 샘플
            체인코드의 샘플이므로 invoke 시에 블럭의 tx를 그냥 저장하는 역활만 합니다.
        """

        def __init__(self):
            ScoreBase.__init__(self)
            self.sample_db = sqlite3.connect('sample_score', check_same_thread=False)
            self.cursor = self.sample_db.cursor()
            self.cursor.execute("CREATE TABLE IF NOT EXISTS BLOCK_TX(Tx_Data text, Tx_hash text, Block_hash text)")
            self.cursor.execute("DELETE FROM BLOCK_TX")

        def invoke(self, tx, block):
            block_tx_list = []
            block_hash = block.block_hash
            tx_data = str(tx.get_data(), 'utf-8')
            tx_hash = tx.tx_hash
            block_tx_list.append((tx_data, tx_hash, block_hash))

            self.cursor.executemany("INSERT INTO BLOCK_TX VALUES(?, ?, ?)", block_tx_list)
            self.sample_db.commit()

        def query(self, **kwargs):
            f = kwargs.get('function')
            if f == 'block_data':
                block_hash = kwargs.get('block_hash')
                return self.cursor.execute('SELECT * FROM BLOCK_TX WHERE Block_hash = ?', [block_hash])
            else:
                return None

        def info(self):
            return None

    def test_invoke_and_query(self):
        """
        생성된 블럭체인에 Score를 실행하고
        체인코드에서 쿼리로 블럭데이터를 가져와, 블럭을 검증하는 테스트 코드
        """

        for x in range(10):
            block = self.generate_block()
            block.block_status = BlockStatus.confirmed
            self.chain.add_block(block)

        block_data = self.score.query(function='block_data', block_hash=self.chain.last_block.block_hash)
        logging.debug("query response: " + str(block_data))
        logging.debug("MK ROOT : %s", self.chain.last_block.merkle_tree_root_hash)
        for row in block_data:
            self.assertEqual(row[2], self.chain.last_block.block_hash)
            block_index = self.chain.last_block.find_transaction_index(row[1])
            logging.debug(block_index)
            logging.debug(self.chain.last_block.mk_merkle_proof(block_index))


if __name__ == '__main__':
    unittest.main()
