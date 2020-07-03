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
"""Test Generator blocks"""

import logging
import os
import unittest

import tests.unit.test_util as test_util
from loopchain import configure as conf
from loopchain.blockchain import BlockChain
from loopchain.blockchain.blocks import Block
from loopchain.crypto.signature import Signer
from loopchain.utils import loggers
from tests.unit.mock_peer import set_mock

loggers.set_preset_type(loggers.PresetType.develop)
loggers.update_preset()


@unittest.skip("BVS")
class TestGeneratorBlock(unittest.TestCase):
    """
    TODO : rewrite this test class
    """
    last_block = None
    __peer_id = 'aaa'

    def setUp(self):
        self.channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL
        test_util.print_testname(self._testMethodName)
        self.peer_auth = Signer.from_prikey(os.urandom(32))

        set_mock(self)

    def tearDown(self):
        pass

    def generate_test_block(self):
        """
        임시 블럭 생성하는 메소드
        :return: 임시 블럭
        """
        if self.last_block is None:
            self.last_block = Block(channel_name=conf.LOOPCHAIN_DEFAULT_CHANNEL)
            self.last_block.generate_block()
        block = Block(channel_name=conf.LOOPCHAIN_DEFAULT_CHANNEL)
        for x in range(0, 10):
            tx = test_util.create_basic_tx(self.__peer_id, self.peer_auth)
            self.assertNotEqual(tx.tx_hash, "", "트랜잭션 생성 실패")
            self.assertTrue(block.put_transaction(tx), "Block에 트랜잭션 추가 실패")
        block.generate_block(self.last_block)
        self.last_block = block
        return block

    def test_block_genesis(self):
        """
        create genesis block
        """
        store_identity = 'genesis_db'
        chain = BlockChain(self.channel_name, store_id=store_identity)
        self.assertIsNotNone(chain.get_blockchain_store(), "impossible create DB")
        block = test_util.add_genesis_block()
        chain.add_block(block)

        self.assertIsNotNone(chain.last_block.block_hash, "impossible create genesis block")
        # remove test DB
        chain.close_blockchain_store()

    def test_block_add(self):
        """
        블럭 추가 테스트
        제네시스 블럭을 만든후 10개의 트랜잭션을 가진 10개의 블럭을 생성하여
        블럭체인에 추가
        """
        store_identity = 'add_test_db'
        # test_store = test_util.make_key_value_store(store_identity)
        chain = BlockChain(self.channel_name, store_id=store_identity)
        self.assertIsNotNone(chain.get_blockchain_store(), "impossible create DB")

        block = test_util.add_genesis_block()
        chain.add_block(block)
        genesis_hash = chain.last_block.block_hash

        for x in range(0,10):
            # 신규 블럭 생성 추가 x 10
            tmp_block = self.generate_test_block()
            tmp_block.block_status = BlockStatus.confirmed
            tmp_block.generate_block(chain.last_block)
            chain.add_block(tmp_block)
            logging.debug("신규 블럭 생성 및 블럭 HASH : %s", chain.last_block.block_hash)

        self.assertNotEqual(genesis_hash, chain.last_block.block_hash, "블럭 추가 불가")

        # 미인증 블럭 추가
        tmp_block = self.generate_test_block()
        tmp_block.block_status = BlockStatus.unconfirmed
        self.assertRaises(TypeError, "미인증 블럭 추가", chain.add_block, tmp_block)

        # Store_data Function 추가
        tmp_block.block_status = BlockStatus.confirmed
        tmp_block.generate_block(chain.last_block)
        # 블럭 저장함수
        last_block_hash = chain.last_block.block_hash

        chain.add_block(tmp_block)

        self.assertNotEqual(last_block_hash, chain.last_block.block_hash)
        self.assertIsNotNone(chain.last_block)

        # remove test DB
        chain.close_blockchain_store()

    def test_block_confirm(self):
        store_identity = 'block_confirm_db'
        chain = BlockChain(self.channel_name, store_id=store_identity)

        self.assertIsNotNone(chain.get_blockchain_store(), "impossible create DB")
        block = test_util.add_genesis_block()
        chain.add_block(block)
        self.last_block = block
        # block을 하나 생성해서 unconfirm 상태에서 추가
        unconfirm_block = self.generate_test_block()
        unconfirm_block.generate_block(chain.last_block)

        self.assertTrue(chain.add_unconfirm_block(unconfirm_block), "미검증블럭 추가에 실패하였습니다.")

        # 블럭 검증작업후 블럭을 검증완료 상태로 바꾸며, 블럭체인에 등록 해 줍니다.
        chain.confirm_prev_block(unconfirm_block)

        # 블럭 검증완료
        self.assertEqual(chain.last_block.block_hash, unconfirm_block.block_hash, "블럭이 추가되지 않았습니다.")

        chain.close_blockchain_store()


if __name__ == '__main__':
    unittest.main()
