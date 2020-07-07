"""Test block chain class"""

import logging
import os
import random
import unittest

import loopchain.utils as util
from loopchain import configure as conf
from loopchain.baseservice import ObjectManager, ScoreResponse
from loopchain.blockchain.blocks import Block
from loopchain.crypto.signature import Signer
from loopchain.utils import loggers
from tests.unit import test_util
from tests.unit.mock_peer import set_mock

loggers.set_preset_type(loggers.PresetType.develop)
loggers.update_preset()


@unittest.skip("BVS")
class TestBlockChain(unittest.TestCase):
    chain = None
    __peer_id = 'aaa'

    def setUp(self):
        test_util.print_testname(self._testMethodName)
        self.peer_auth = Signer.from_prikey(os.urandom(32))

        set_mock(self)
        # BlockChain 을 만듬
        self.test_store = test_util.make_key_value_store('blockchain_db')
        self.assertIsNotNone(self.test_store, "DB생성 불가")
        self.chain = BlockChain(self.test_store)

    def tearDown(self):
        # Blockchain을 삭제
        ObjectManager().peer_service = None
        self.test_store.destroy_store()
        os.system("rm -rf ./blockchain_db*")

    def generate_test_block(self):
        """
        임시 블럭 생성하는 메소드
        :return: 임시 블럭
        """

        block = Block(channel_name=conf.LOOPCHAIN_DEFAULT_CHANNEL)
        for x in range(0, 10):
            tx = test_util.create_basic_tx(self.__peer_id, self.peer_auth)
            self.assertNotEqual(tx.tx_hash, "", "트랜잭션 생성 실패")
            self.assertTrue(block.put_transaction(tx), "Block에 트랜잭션 추가 실패")

        return block

    def test_genesis_block_by_key(self):
        """
        제네시스 블럭을 찾는다
        """
        # 키를 통하여 블럭을 찾는다
        block = test_util.add_genesis_block()
        self.chain.add_block(block)

        last_block_hash = self.chain.last_block.block_hash
        logging.debug("LAST BLOCK : %s", last_block_hash)
        last_block = self.chain.find_block_by_hash(last_block_hash)
        self.assertIsNotNone(last_block, "제네시스 블럭을 가져올 수 없습니다.")

    def test_find_do_not_exist_block(self):
        """
        블럭체인에 없는 블럭을 찾는다
        """
        none_block_key = "bf5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc"
        none_block = self.chain.find_block_by_hash(none_block_key)
        self.assertIsNot(none_block, "존재하지 않는 블럭이 출력되었습니다.")

    @unittest.skip
    def test_nonce(self):
        """test get, verify, set nonce

        :return:
        """
        # GIVEN
        new_nonce = self.chain.get_new_nonce_by_address("ABC")
        util.logger.spam(f"test_blockchain:test_nonce new_nonce({new_nonce})")

        # WHEN
        verify_result = self.chain.verify_nonce_by_address("ABC", new_nonce)
        util.logger.spam(f"test_blockchain:test_nonce verify_result({verify_result})")
        self.assertTrue(verify_result)
        set_result = self.chain._BlockChain__set_nonce_by_address("ABC", new_nonce)
        self.assertTrue(set_result)

        # THEN
        next_new_nonce = self.chain.get_new_nonce_by_address("ABC")
        util.logger.spam(f"test_blockchain:test_nonce new_nonce({next_new_nonce})")
        self.assertEqual(hex(int(new_nonce, 16) + 1), next_new_nonce)

    def test_find_block_by_height(self):
        # GIVEN
        size = 10
        find_block_index = int(size*random.random())
        find_block_height = 0
        find_block_hash = None
        for x in range(size):
            last_block = self.chain.last_block
            n_block = self.generate_test_block()
            n_block.generate_block(last_block)
            n_block.block_status = BlockStatus.confirmed
            if find_block_index == x:
                find_block_hash = n_block.block_hash
                find_block_height = n_block.height
            self.chain.add_block(n_block)

        logging.debug("find block hash : %s ", find_block_hash)
        logging.debug("find block height : %d ", find_block_height)

        # WHEN
        find_block_by_hash = self.chain.find_block_by_hash(find_block_hash)
        find_block_by_height = self.chain.find_block_by_height(find_block_height)

        # THEN
        self.assertEqual(find_block_by_hash.block_hash, find_block_by_height.block_hash)

    def test_add_some_block_and_find_by_key(self):
        """몇개의 블럭을 추가한 후 임의의 블럭을 찾는다
        """
        # GIVEN
        size = 10
        find_block_index = int(size*random.random())
        find_block_hash = None
        for x in range(size):
            last_block = self.chain.last_block
            n_block = self.generate_test_block()
            n_block.generate_block(last_block)
            n_block.block_status = BlockStatus.confirmed
            if find_block_index == x:
                find_block_hash = n_block.block_hash
            logging.debug("new block height : %i", n_block.height)
            self.chain.add_block(n_block)

        logging.debug("find block index : %i ", find_block_index)
        logging.debug("find block hash : %s ", find_block_hash)

        # WHEN
        find_block = self.chain.find_block_by_hash(find_block_hash)
        logging.debug("find block height : %i", find_block.height)

        # THEN
        self.assertEqual(find_block_hash, find_block.block_hash)

    def test_add_and_find_tx(self):
        """block db 에 block_hash - block_object 를 저장할때, tx_hash - tx_object 도 저장한다.
        get tx by tx_hash 시 해당 block 을 효율적으로 찾기 위해서
        """
        tx = self.__add_single_tx_block_blockchain_return_tx()
        logging.debug("add tx hash : " + tx.tx_hash)

        saved_tx = self.chain.find_tx_by_key(tx.tx_hash)
        logging.debug("saved_tx: " + str(saved_tx.tx_hash))

        self.assertEqual(tx.tx_hash, saved_tx.tx_hash, "Fail Find Transaction")

    def test_add_and_verify_results(self):
        """invoke_result = "{"code" : "invoke_result_code" , "error_message": "message" }"

        """
        test_util.add_genesis_block()
        block = test_util.add_genesis_block()
        self.chain.add_block(block)

        tx = self.__add_single_tx_block_blockchain_return_tx()

        invoke_result = self.chain.find_invoke_result_by_tx_hash(tx.tx_hash)
        self.assertEqual(invoke_result['code'], ScoreResponse.SUCCESS)

    def __add_single_tx_block_blockchain_return_tx(self):
        last_block = self.chain.last_block
        block = Block(channel_name=conf.LOOPCHAIN_DEFAULT_CHANNEL)
        tx = test_util.create_basic_tx(self.__peer_id, self.peer_auth)
        block.put_transaction(tx)

        logging.debug("tx_hash: " + tx.tx_hash)

        block.generate_block(last_block)
        block.block_status = BlockStatus.confirmed

        # add_block to blockchain
        self.assertTrue(self.chain.add_block(block),
                        "Fail Add Block to BlockChain")
        return tx

    def test_unicode_decode_error(self):
        """ Transaction hash 는 UTF-8 인코딩이나 block hash 값은 sha256 hex byte array 이므로 인코딩 에러가 발생함
        """
        test_util.add_genesis_block()
        block = test_util.add_genesis_block()
        self.chain.add_block(block)

        last_block = self.chain.last_block
        unexpected_transaction = self.chain.find_tx_by_key(last_block.block_hash)
        self.assertIsNone(unexpected_transaction, "unexpected_transaction is not None")

    # blockchain is no more singleton. (for multi chain)
    @unittest.skip
    def test_blockchain_is_singleton(self):
        x = BlockChain(test_util.make_key_value_store())
        y = BlockChain(test_util.make_key_value_store())

        self.assertTrue((x is y))


if __name__ == '__main__':
    unittest.main()
