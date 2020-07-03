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
"""Test Candidate Blocks"""

import unittest

import loopchain.utils as util
import tests.unit.test_util as test_util
from loopchain.blockchain import CandidateBlock, CandidateBlocks, BlockChain, ExternalAddress
from loopchain.blockchain.blocks import BlockBuilder
from loopchain.blockchain.transactions import TransactionVersioner
from loopchain.utils import loggers

loggers.set_preset_type(loggers.PresetType.develop)
loggers.update_preset()


class TestCandidateBlocks(unittest.TestCase):
    def setUp(self):
        test_util.print_testname(self._testMethodName)

    def tearDown(self):
        pass

    @staticmethod
    def __get_test_block():
        block_builder = BlockBuilder.new("0.1a", TransactionVersioner())
        block_builder.height = 0
        block_builder.prev_hash = None
        block = block_builder.build()  # It does not have commit state. It will be rebuilt.
        return block

    def test_generate_candidate_block_by_block(self):
        # GIVEN
        block = self.__get_test_block()

        # WHEN
        candidate_block = CandidateBlock.from_block(block, [])
        util.logger.spam(f"block hash({block.header.hash}) candidate hash({candidate_block.hash})")

        # THEN
        self.assertEqual(block.header.hash, candidate_block.hash)
        self.assertIsNotNone(candidate_block.block)

    def test_generate_candidate_block_by_hash_first(self):
        # GIVEN
        block = self.__get_test_block()

        # WHEN CandidateBlock.from_hash
        candidate_block = CandidateBlock.from_hash(block.header.hash, block.header.height)
        util.logger.spam(f"block hash({block.header.hash}) candidate hash({candidate_block.hash})")

        # THEN
        self.assertEqual(block.header.hash, candidate_block.hash)
        self.assertIsNone(candidate_block.block)

        # WHEN Set candidate_block.block
        candidate_block.add_block(block, [])

        # THEN
        self.assertEqual(block.header.hash, candidate_block.hash)
        self.assertIsNotNone(candidate_block.block)

    def test_add_remove_block_to_candidate_blocks(self):
        # GIVEN
        block0 = self.__get_test_block()
        block0.header.__dict__['height'] = -1
        block = self.__get_test_block()
        blockchain = BlockChain('icon_dex', 'icon_dex', self)
        blockchain.__dict__['_BlockChain__last_block'] = block0
        candidate_blocks = CandidateBlocks(blockchain)

        # WHEN add
        candidate_blocks.add_block(block, [ExternalAddress.empty()])

        # THEN
        self.assertTrue(block.header.hash in candidate_blocks.blocks)

        # WHEN remove
        candidate_blocks.remove_block(block.header.hash)

        # THEN
        self.assertFalse(block.header.hash in candidate_blocks.blocks)


if __name__ == '__main__':
    unittest.main()
