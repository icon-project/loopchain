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
"""Block chain class with authorized blocks only"""

import copy
import json
import leveldb
import pickle
import threading
from enum import Enum

import loopchain.utils as util
from loopchain import configure as conf
from loopchain.baseservice import ScoreResponse, ObjectManager
from loopchain.blockchain import BlockStatus, Block, Transaction, \
    TransactionStatusInQueue
from loopchain.blockchain.exception import *
from loopchain.blockchain.score_base import *
from loopchain.blockchain.validator import get_genesis_tx_validator
from loopchain.channel.channel_property import ChannelProperty
from loopchain.protos import message_code
from loopchain.utils.message_queue import StubCollection


class NID(Enum):
    mainnet = "0x1"
    testnet = "0x2"
    unknown = "0x3"


class BlockChain:
    """Block chain with only committed blocks."""

    NID_KEY = b'NID_KEY'
    UNCONFIRM_BLOCK_KEY = b'UNCONFIRM_BLOCK'
    PRECOMMIT_BLOCK_KEY = b'PRECOMMIT_BLOCK'
    TRANSACTION_COUNT_KEY = b'TRANSACTION_COUNT'
    LAST_BLOCK_KEY = b'last_block_key'
    BLOCK_HEIGHT_KEY = b'block_height_key'
    INVOKE_RESULT_BLOCK_HEIGHT_KEY = b'invoke_result_block_height_key'

    def __init__(self, blockchain_db=None, channel_name=None):
        if channel_name is None:
            channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL
        self.__block_height = -1
        self.__last_block = None
        self.__save_tx_by_address_strategy = None
        self.__channel_name = channel_name
        self.__set_send_tx_type(conf.CHANNEL_OPTION[channel_name]["send_tx_type"])

        self.__peer_id = None
        if ObjectManager().peer_service is not None:
            self.__peer_id = ObjectManager().peer_service.peer_id

        # block db has [ block_hash - block | block_height - block_hash | BlockChain.LAST_BLOCK_KEY - block_hash ]
        self.__confirmed_block_db = blockchain_db
        # logging.debug(f"BlockChain::init confirmed_block_db({self.__confirmed_block_db})")

        if self.__confirmed_block_db is None:
            try:
                self.__confirmed_block_db = leveldb.LevelDB(conf.DEFAULT_LEVEL_DB_PATH)
            except leveldb.LevelDBError:
                raise leveldb.LevelDBError("Fail To Create Level DB(path): " + conf.DEFAULT_LEVEL_DB_PATH)

        # made block count as a leader
        self.__made_block_count = 0
        self.__invoke_results = {}

        self.last_commit_state_height = 0
        self.last_commit_state = {}
        self.__add_block_lock = threading.Lock()
        self.__confirmed_block_lock = threading.Lock()

        self.__total_tx = 0

    def __set_send_tx_type(self, send_tx_type):
        if send_tx_type == conf.SendTxType.icx:
            self.__save_tx_by_address_strategy = self.__save_tx_by_address
        else:
            self.__save_tx_by_address_strategy = self.__save_tx_by_address_pass

    def close_blockchain_db(self):
        del self.__confirmed_block_db
        self.__confirmed_block_db = None

    @property
    def block_height(self):
        return self.__block_height

    @property
    def total_tx(self):
        return self.__total_tx

    @property
    def last_block(self) -> Block:
        try:
            logging.debug(f"ENGINE-303 blockchain last_block: {self.__last_block.height}, {self.__last_block.block_hash}")
        except:
            pass
        return self.__last_block

    @property
    def made_block_count(self):
        return self.__made_block_count

    def increase_made_block_count(self):
        self.__made_block_count += 1

    def reset_made_block_count(self):
        self.__made_block_count = 0

    def rebuild_transaction_count(self):
        if self.__last_block is not None:
            # rebuild blocks to Genesis block.
            logging.info("re-build transaction count from DB....")

            if conf.READ_CACHED_TX_COUNT:
                try:
                    self.__total_tx = self._rebuild_transaction_count_from_cached()
                except Exception as e:
                    if isinstance(e, KeyError):
                        logging.warning(f"Cannot find 'TRANSACTION_COUNT' Key from DB. Rebuild tx count")
                    else:
                        logging.warning(f"Exception raised on getting 'TRANSACTION_COUNT' from DB. Rebuild tx count,"
                                        f"Exception : {type(e)}, {e}")
                    self.__total_tx = self._rebuild_transaction_count_from_blocks()
            else:
                self.__total_tx = self._rebuild_transaction_count_from_blocks()

            logging.info(f"rebuilt blocks, total_tx: {self.__total_tx}")
            logging.info(f"block hash({self.__last_block.block_hash}) and height({self.__last_block.height})")
            return True
        else:
            logging.info("There is no block.")
            return False

    def _rebuild_transaction_count_from_blocks(self):
        total_tx = 0
        block_hash = self.__last_block.block_hash
        while block_hash != "":
            block_dump = self.__confirmed_block_db.Get(block_hash.encode(encoding='UTF-8'))
            block = Block(channel_name=self.__channel_name)
            block.deserialize_block(block_dump)

            # Count only normal block`s tx count, not genesis block`s
            if block.height > 0:
                total_tx += block.confirmed_tx_len

            block_hash = block.prev_block_hash
        return total_tx

    def _rebuild_transaction_count_from_cached(self):
        tx_count_bytes = self.__confirmed_block_db.Get(BlockChain.TRANSACTION_COUNT_KEY)
        return int.from_bytes(tx_count_bytes, byteorder='big')

    def __find_block_by_key(self, key):

        try:
            block_bytes = self.__confirmed_block_db.Get(key)
            block = Block(channel_name=self.__channel_name)
            block.deserialize_block(block_bytes)
        except KeyError as e:
            block = None
            logging.error(f"__find_block_by_key::KeyError block_hash({key}) error({e})")

        return block

    def find_block_by_hash(self, block_hash):
        """find block by block hash.

        :param block_hash: plain string,
        key 로 사용되기전에 함수내에서 encoding 되므로 미리 encoding 된 key를 parameter 로 사용해선 안된다.
        :return: None or Block
        """
        return self.__find_block_by_key(block_hash.encode(encoding='UTF-8'))

    def find_block_by_height(self, block_height):
        """find block by its height

        :param block_height: int,
        it convert to key of blockchain db in this method so don't try already converted key.
        :return None or Block
        """
        if block_height == -1:
            return self.__last_block

        try:
            key = self.__confirmed_block_db.Get(BlockChain.BLOCK_HEIGHT_KEY +
                                                block_height.to_bytes(conf.BLOCK_HEIGHT_BYTES_LEN, byteorder='big'))
        except KeyError:
            return None

        return self.__find_block_by_key(key)

    def __score_invoke_with_state_integrity(self, block: Block, is_commit_state_validation=False):
        if is_commit_state_validation:
            self.last_commit_state = copy.deepcopy(block.commit_state)
            invoke_results = ObjectManager().channel_service.score_invoke(block)

            if self.last_commit_state != block.commit_state:
                util.logger.spam(f"last_commit_state({self.last_commit_state})")
                util.logger.spam(f"block.commit_state({block.commit_state})")
                util.exit_and_msg(f"add_block FAIL commit state integrity!! This Peer will Down.")
            self.last_commit_state_height = block.height
        else:
            invoke_results = ObjectManager().channel_service.score_invoke(block)

        return invoke_results

    def add_block(self, block: Block, is_commit_state_validation=False) -> bool:
        """add committed block

        :param block: a block after confirmation
        'STORE_VALID_TRANSACTION_ONLY'가 True로 설정 된 경우, 필수 parameter.
        :param is_commit_state_validation: if True: add only commit state validate pass
        :return: to add block is success or not
        """

        with self.__add_block_lock:
            util.logger.spam(f"ENGINE-308 blockchain:add_block is_commit_state_validation({is_commit_state_validation})")

            if block.height != 0 and block.height != (self.last_block.height + 1) and not is_commit_state_validation:
                logging.warning(f"blockchain:add_block invalid block height({block.height})")
                return False

            try:
                self.__verify_block_connection(block)
            except Exception as e:
                logging.error(f"add_block error! caused by : {e}")
                return False

            if conf.CHANNEL_OPTION[self.__channel_name]["send_tx_type"] == conf.SendTxType.icx and block.height == 0:
                invoke_results = ObjectManager().channel_service.genesis_invoke(block)
                ObjectManager().channel_service.score_write_precommit_state(block)
                self.__add_tx_to_block_db(block, invoke_results)
            elif not conf.CHANNEL_OPTION[self.__channel_name]['store_valid_transaction_only']:
                # STORE_VALID_TRANSACTION_ONLY
                if block.height == 0 or ObjectManager().channel_service is None:
                    # all results to success
                    success_result = {'code': int(message_code.Response.success)}
                    invoke_results = util.create_invoke_result_specific_case(
                        block.confirmed_transaction_list, success_result)
                    self.__add_tx_to_block_db(block, invoke_results)
                else:
                    try:
                        invoke_results = self.__score_invoke_with_state_integrity(block, is_commit_state_validation)
                    except Exception as e:
                        # When Grpc Connection Raise Exception
                        # save all result{'code': ScoreResponse.SCORE_CONTAINER_EXCEPTION, 'message': str(e)}
                        logging.error(f'Error While Invoke Score fail add block : {e}')
                        score_container_exception_result = {
                            'code': ScoreResponse.SCORE_CONTAINER_EXCEPTION, 'message': str(e)}
                        invoke_results = \
                            util.create_invoke_result_specific_case(
                                block.confirmed_transaction_list,
                                score_container_exception_result
                            )
                    self.__add_tx_to_block_db(block, invoke_results)
                    ObjectManager().channel_service.score_write_precommit_state(block)
            else:
                need_to_commit = True
                invoke_results = self.__invoke_results.get(block.block_hash, None)
                if not invoke_results:
                    need_to_commit = self.__prevent_next_block_mismatch(block, is_commit_state_validation)
                    if need_to_commit:
                        invoke_results = self.__score_invoke_with_state_integrity(block, is_commit_state_validation)

                try:
                    if need_to_commit:
                        self.__add_tx_to_block_db(block, invoke_results)
                        ObjectManager().channel_service.score_write_precommit_state(block)
                        # invoke_results = self.__invoke_results[block.block_hash]
                except Exception as e:
                    logging.warning(f"blockchain:add_block FAIL "
                                    f"channel_service.score_write_precommit_state")
                    raise e
                finally:
                    self.__invoke_results.pop(block.block_hash, None)

            # a condition for the exception case of genesis block.
            next_total_tx = self.__total_tx
            if block.height > 0:
                next_total_tx += block.confirmed_tx_len

            bit_length = next_total_tx.bit_length()
            byte_length = (bit_length + 7) // 8
            next_total_tx_bytes = next_total_tx.to_bytes(byte_length, byteorder='big')

            block_hash_encoded = block.block_hash.encode(encoding='UTF-8')

            batch = leveldb.WriteBatch()
            batch.Put(block_hash_encoded, block.serialize_block())
            batch.Put(BlockChain.LAST_BLOCK_KEY, block_hash_encoded)
            batch.Put(BlockChain.TRANSACTION_COUNT_KEY, next_total_tx_bytes)
            batch.Put(
                BlockChain.BLOCK_HEIGHT_KEY +
                block.height.to_bytes(conf.BLOCK_HEIGHT_BYTES_LEN, byteorder='big'),
                block_hash_encoded)
            self.__confirmed_block_db.Write(batch)

            self.__last_block = block
            self.__block_height = self.__last_block.height
            self.__total_tx = next_total_tx
            logging.debug(f"blockchain add_block set block_height({self.__block_height}), "
                          f"last_block({self.__last_block.block_hash})")
            logging.info(
                f"ADD BLOCK HEIGHT : {block.height} , HASH : {block.block_hash} , CHANNEL : {self.__channel_name}")

            util.apm_event(self.__peer_id, {
                'event_type': 'AddBlock',
                'peer_id': self.__peer_id,
                'peer_name': conf.PEER_NAME,
                'channel_name': self.__channel_name,
                'data': {
                    'block_height': self.__block_height,
                    'block_type': block.block_type.name}})

            return True

    def __prevent_next_block_mismatch(self, next_block: Block, is_commit_state_validation: bool) -> bool:
        logging.debug(f"prevent_block_mismatch...")
        if util.channel_use_icx(self.__channel_name):
            score_stub = StubCollection().icon_score_stubs[self.__channel_name]
            request = {
                "method": "ise_getStatus",
                "params": {"filter": ["lastBlock"]}
            }

            response = score_stub.sync_task().query(request)
            score_last_block_height = int(response['lastBlock']['blockHeight'], 16)

            if score_last_block_height == next_block.height:
                logging.debug(f"already invoked block in score...")
                return False
            elif score_last_block_height < next_block.height:
                for invoke_block_height in range(score_last_block_height + 1, next_block.height):
                    logging.debug(f"mismatch invoke_block_height({invoke_block_height}) "
                                  f"score_last_block_height({score_last_block_height}) "
                                  f"next_block_height({next_block.height})")

                    invoke_block = self.find_block_by_height(invoke_block_height)
                    if invoke_block is None:
                        raise RuntimeError("Error raised during prevent mismatch block, "
                                           f"Cannot find block({invoke_block_height}")

                    invoke_block_result = self.__score_invoke_with_state_integrity(
                        invoke_block, is_commit_state_validation
                    )

                    self.__add_tx_to_block_db(invoke_block, invoke_block_result)
                    ObjectManager().channel_service.score_write_precommit_state(invoke_block)

                return True
            else:
                if score_last_block_height == next_block.height + 1:
                    try:
                        invoke_result_block_height_bytes = \
                            self.__confirmed_block_db.Get(BlockChain.INVOKE_RESULT_BLOCK_HEIGHT_KEY)
                        invoke_result_block_height = int.from_bytes(invoke_result_block_height_bytes, byteorder='big')

                        if invoke_result_block_height == next_block.height:
                            logging.debug(f"already saved invoke result...")
                            return False
                    except KeyError:
                        logging.debug(f"There is no invoke result height in db.")
                else:
                    util.exit_and_msg("Too many different(over 2) of block height between the loopchain and score. "
                                      "Peer will be down. : "
                                      f"loopchain({next_block.height})/score({score_last_block_height})")

                return True

    def __verify_block_connection(self, block):
        if block.block_status is not BlockStatus.confirmed:
            raise BlockInValidError("미인증 블럭")
        elif self.__last_block is not None and self.__last_block.height > 0:
            if self.__last_block.block_hash != block.prev_block_hash:
                # 마지막 블럭의 hash값이 추가되는 블럭의 prev_hash값과 다르면 추가 하지 않고 익셉션을 냅니다.
                raise BlockError(f"HEIGHT({block.height}), "
                                 f"prev_block_hash must({block.prev_block_hash}) "
                                 f"be same with the last block({self.__last_block.block_hash})")

    def __add_tx_to_block_db(self, block, invoke_results):
        """block db 에 block_hash - block_object 를 저장할때, tx_hash - block_hash 를 저장한다.
        get tx by tx_hash 시 해당 block 을 효율적으로 찾기 위해서
        :param block:
        """
        # loop all tx in block
        logging.debug("try add all tx in block to block db, block hash: " + block.block_hash)
        block_manager = ObjectManager().channel_service.block_manager
        tx_queue = block_manager.get_tx_queue()
        # util.logger.spam(f"blockchain:__add_tx_to_block_db::tx_queue : {tx_queue}")
        # util.logger.spam(
        #     f"blockchain:__add_tx_to_block_db::confirmed_transaction_list : {block.confirmed_transaction_list}")

        for index, tx in enumerate(block.confirmed_transaction_list):
            tx_hash = tx.tx_hash
            invoke_result = invoke_results[tx_hash]

            tx_info = {
                'block_hash': block.block_hash,
                'block_height': block.height,
                'tx_index': hex(index),
                'transaction': tx.icx_origin_data_v3,
                'result': invoke_result
            }

            self.__confirmed_block_db.Put(
                tx_hash.encode(encoding=conf.HASH_KEY_ENCODING),
                json.dumps(tx_info).encode(encoding=conf.PEER_DATA_ENCODING))

            # try:
            #     util.logger.spam(
            #         f"blockchain:__add_tx_to_block_db::{tx_hash}'s status : {tx_queue.get_item_status(tx_hash)}")
            # except KeyError as e:
            #     util.logger.spam(f"__add_tx_to_block_db :: {e}")

            tx_queue.pop(tx_hash, None)
            # util.logger.spam(f"pop tx from queue:{tx_hash}")

            if block.height > 0:
                self.__save_tx_by_address_strategy(tx)

        self.__save_invoke_result_block_height(block.height)

    def __save_invoke_result_block_height(self, height):
        bit_length = height.bit_length()
        byte_length = (bit_length + 7) // 8
        block_height_bytes = height.to_bytes(byte_length, byteorder='big')
        self.__confirmed_block_db.Put(
            BlockChain.INVOKE_RESULT_BLOCK_HEIGHT_KEY,
            block_height_bytes
        )

    def __precommit_tx(self, precommit_block):
        """ change status of transactions in a precommit block
        :param block:
        """
        # loop all tx in block
        logging.debug("try to change status to precommit in queue, block hash: " + precommit_block.block_hash)
        tx_queue = ObjectManager().channel_service.block_manager.get_tx_queue()
        # util.logger.spam(f"blockchain:__precommit_tx::tx_queue : {tx_queue}")

        for tx in precommit_block.confirmed_transaction_list:
            tx_hash = tx.tx_hash
            if tx_queue.get_item_in_status(TransactionStatusInQueue.normal, TransactionStatusInQueue.normal):
                try:
                    tx_queue.set_item_status(tx_hash, TransactionStatusInQueue.precommited_to_block)
                    # util.logger.spam(
                    #     f"blockchain:__precommit_tx::{tx_hash}'s status : {tx_queue.get_item_status(tx_hash)}")
                except KeyError as e:
                    logging.warning(f"blockchain:__precommit_tx::KeyError:There is no tx by hash({tx_hash})")

    def __save_tx_by_address(self, tx: Transaction):
        address = tx.icx_origin_data['from']
        return self.add_tx_to_list_by_address(address, tx.tx_hash)

    def __save_tx_by_address_pass(self, tx):
        return True

    @staticmethod
    def __get_tx_list_key(address, index):
        return conf.TX_LIST_ADDRESS_PREFIX + (address + str(index)).encode(encoding=conf.HASH_KEY_ENCODING)

    def get_tx_list_by_address(self, address, index=0):
        list_key = self.__get_tx_list_key(address, index)

        try:
            tx_list = pickle.loads(self.__confirmed_block_db.Get(list_key))
            next_index = tx_list[-1]
        except KeyError:
            tx_list = [0]  # 0 means there is no more list after this.
            next_index = 0

        return tx_list, next_index

    def get_precommit_block(self):
        return self.__find_block_by_key(BlockChain.PRECOMMIT_BLOCK_KEY)

    def find_nid(self):
        try:
            nid = self.__confirmed_block_db.Get(BlockChain.NID_KEY)
            return nid.decode(conf.HASH_KEY_ENCODING)
        except KeyError as e:
            logging.debug(f"blockchain:get_nid::There is no NID.")
            return None

    def add_tx_to_list_by_address(self, address, tx_hash):
        current_list, current_index = self.get_tx_list_by_address(address, 0)

        if len(current_list) > conf.MAX_TX_LIST_SIZE_BY_ADDRESS:
            new_index = current_index + 1
            new_list_key = self.__get_tx_list_key(address, new_index)
            self.__confirmed_block_db.Put(new_list_key, pickle.dumps(current_list))
            current_list = [new_index]

        current_list.insert(0, tx_hash)
        list_key = self.__get_tx_list_key(address, 0)
        self.__confirmed_block_db.Put(list_key, pickle.dumps(current_list))

        return True

    def find_tx_by_key(self, tx_hash_key):
        """tx 의 hash 로 저장된 tx 를 구한다.

        :param tx_hash_key: tx 의 tx_hash
        :return tx_hash_key 에 해당하는 transaction, 예외인 경우 None 을 리턴한다.
        """
        # levle db 에서 tx 가 저장된 block 의 hash 를 구한다.
        try:
            tx_info_json = self.find_tx_info(tx_hash_key)
        except KeyError as e:
            # Client 의 잘못된 요청이 있을 수 있으므로 Warning 처리후 None 을 리턴한다.
            # 시스템 Error 로 처리하지 않는다.
            # logging.warning(f"[blockchain::find_tx_by_key] Transaction is pending. tx_hash ({tx_hash_key})")
            return None
        if tx_info_json is None:
            logging.warning(f"tx not found. tx_hash ({tx_hash_key})")
            return None
        block_key = tx_info_json['block_hash']
        logging.debug("block_key: " + str(block_key))

        # block 의 hash 로 block object 를 구한다.
        block = self.find_block_by_hash(block_key)
        logging.debug("block: " + block.block_hash)
        if block is None:
            logging.error("There is No Block, block_hash: " + block.block_hash)
            return None

        # block object 에서 저장된 tx 를 구한다.
        tx = block.find_tx_by_hash(tx_hash_key)
        if not tx:
            logging.error(f"block.find_tx_by_hash tx_hash error({tx_hash_key})")
            return None

        logging.debug("find tx: " + tx.tx_hash)

        return tx

    def find_invoke_result_by_tx_hash(self, tx_hash):
        """find invoke result matching tx_hash and return result if not in blockchain return code delay

        :param tx_hash: tx_hash
        :return: {"code" : "code", "error_message" : "error_message if not fail this is not exist"}
        """
        try:
            tx_info = self.find_tx_info(tx_hash)
        except KeyError as e:
            block_manager = ObjectManager().channel_service.block_manager
            if tx_hash in block_manager.get_tx_queue():
                # this case is tx pending
                logging.debug(f"blockchain:find_invoke_result_by_tx_hash pending tx({tx_hash})")
                return {'code': ScoreResponse.NOT_INVOKED}
            else:
                logging.debug("blockchain::find invoke_result KeyError: " + str(e))
                # This transaction is considered a failure.
                return {'code': ScoreResponse.NOT_EXIST}

        return tx_info['result']

    def find_tx_info(self, tx_hash_key):
        try:
            tx_info = self.__confirmed_block_db.Get(
                tx_hash_key.encode(encoding=conf.HASH_KEY_ENCODING))
            tx_info_json = json.loads(tx_info, encoding=conf.PEER_DATA_ENCODING)

        except UnicodeDecodeError as e:
            logging.warning("blockchain::find_tx_by_key: UnicodeDecodeError: " + str(e))
            return None
        # except KeyError as e:
        #     logging.debug("blockchain::find_tx_by_key: not found tx: " + str(e))
        #     return None

        return tx_info_json

    def __add_genesisblock(self, tx_info: dict=None):
        """제네시스 블럭을 추가 합니다.

        :param tx_info: Transaction data for making genesis block from an initial file
        :return:
        """
        logging.info("Make Genesis Block....")
        block = Block(channel_name=self.__channel_name)
        block.block_status = BlockStatus.confirmed
        if tx_info:
            keys = tx_info.keys()
            if "accounts" in keys and "message" in keys:
                genesis_validator = get_genesis_tx_validator(self.__channel_name)
                is_valid, tx = genesis_validator.init_genesis_tx(tx_info)
                if is_valid:
                    block.put_genesis_transaction(tx)
                else:
                    raise TransactionInvalidError(message=
                                                  f"The Genesis block data is invalid."
                                                  f"That's why Genesis block couldn't be generated.")

        block.generate_block()
        self.add_block(block)

    def __put_block_to_db(self, block_key, block):
        # confirm 블럭
        if (self.__last_block.height + 1) != block.height:
            logging.error("The height of the blockchain is different.")
            return False, "block_height"
        elif block.prev_block_hash != self.__last_block.block_hash:
            logging.error(f"The hash of the last block is different. "
                          f"block's prev_hash({block.prev_block_hash}) vs "
                          f"last_block's hash({self.__last_block.block_hash})")
            return False, "prev_block_hash"
        elif block.block_hash != block.generate_block(self.__last_block):
            logging.error(f"The block_hash({block.block_hash}) is different from self-generated block's hash.")
            return False, "generate_block_hash"

        # Save unconfirmed_block
        # Save and Get Unconfirmed block using pickle for unserialized info(commit_state)
        # self.__confirmed_block_db.Put(BlockChain.UNCONFIRM_BLOCK_KEY, unconfirmed_block.serialize_block())
        self.__confirmed_block_db.Put(block_key, pickle.dumps(block))
        return True, "No reason"

    def add_unconfirm_block(self, unconfirmed_block):
        """인증되지 않은 Unconfirm블럭을 추가 합니다.

        :param unconfirmed_block: 인증되지 않은 Unconfirm블럭
        :return:인증값 : True 인증 , False 미인증
        """
        logging.debug(
            f"blockchain:add_unconfirmed_block ({self.__channel_name}), hash ({unconfirmed_block.block_hash})")

        return self.__put_block_to_db(BlockChain.UNCONFIRM_BLOCK_KEY, unconfirmed_block)

    def put_precommit_block(self, precommit_block: Block):
        # write precommit block to DB
        logging.debug(
            f"blockchain:put_precommit_block ({self.__channel_name}), hash ({precommit_block.block_hash})")
        if self.__last_block.height < precommit_block.height:
            self.__precommit_tx(precommit_block)
            util.logger.spam(f"blockchain:put_precommit_block:confirmed_transaction_list")
            # for tx in precommit_block.confirmed_transaction_list:
            #     tx_hash = tx.tx_hash
            #     util.logger.spam(f"blockchain.py:put_precommit_block:{tx_hash}")

            results = self.__confirmed_block_db.Put(BlockChain.PRECOMMIT_BLOCK_KEY, precommit_block.serialize_block())

            util.logger.spam(f"result of to write to db ({results})")
            logging.info(f"ADD BLOCK PRECOMMIT HEIGHT : {precommit_block.height} , "
                         f"HASH : {precommit_block.block_hash}, CHANNEL : {self.__channel_name}")
        else:
            results = None
            logging.debug(f"blockchain:put_precommit_block::this precommit block is not validate. "
                          f"the height of precommit block must be bigger than the last block."
                          f"(last block:{self.__last_block.height}/precommit block:{precommit_block.height})")

        return results

    def put_nid(self, nid: str):
        """
        write nid to DB
        :param nid: Network ID
        :return:
        """
        util.logger.spam(f"blockchain:put_nid ({self.__channel_name}), nid ({nid})")
        if nid is None:
            return

        results = self.__confirmed_block_db.Put(BlockChain.NID_KEY, nid.encode(encoding=conf.HASH_KEY_ENCODING))
        util.logger.spam(f"result of to write to db ({results})")

        return results

    def confirm_block(self, confirmed_block_hash):
        """인증완료후 Block을 Confirm해 줍니다.

        :param confirmed_block_hash: 인증된 블럭의 hash
        :return: confirm_Block
        """
        with self.__confirmed_block_lock:
            logging.debug(f"BlockChain:confirm_block channel({self.__channel_name})")

            try:
                # Save and Get Unconfirmed block using pickle for unserialized info(commit_state)
                # unconfirmed_block_byte = self.__confirmed_block_db.Get(BlockChain.UNCONFIRM_BLOCK_KEY)
                unconfirmed_block = pickle.loads(self.__confirmed_block_db.Get(BlockChain.UNCONFIRM_BLOCK_KEY))

            except KeyError:
                except_msg = f"there is no unconfirmed block in this peer block_hash({confirmed_block_hash})"
                logging.warning(except_msg)
                raise BlockchainError(except_msg)

            # unconfirmed_block = Block(channel_name=self.__channel_name)
            # unconfirmed_block.deserialize_block(unconfirmed_block_byte)

            if unconfirmed_block.block_hash != confirmed_block_hash:
                logging.warning("It's not possible to add block while check block hash is fail-")
                raise BlockchainError('확인하는 블럭 해쉬 값이 다릅니다.')

            logging.debug("unconfirmed_block.block_hash: " + unconfirmed_block.block_hash)
            logging.debug("confirmed_block_hash: " + confirmed_block_hash)
            logging.debug("unconfirmed_block.prev_block_hash: " + unconfirmed_block.prev_block_hash)

            is_commit_state_validation = False
            if conf.CHANNEL_OPTION[self.__channel_name]["send_tx_type"] == conf.SendTxType.icx:
                is_commit_state_validation = True

            unconfirmed_block.block_status = BlockStatus.confirmed
            # Block Validate and save Block
            self.add_block(unconfirmed_block, is_commit_state_validation)
            self.__confirmed_block_db.Delete(BlockChain.UNCONFIRM_BLOCK_KEY)

            return unconfirmed_block

    def init_block_chain(self, is_leader=False):
        # level DB에서 블럭을 읽어 들이며, 만약 levelDB에 블럭이 없을 경우 제네시스 블럭을 만든다
        try:
            last_block_key = self.__confirmed_block_db.Get(BlockChain.LAST_BLOCK_KEY, True)
        except KeyError:
            last_block_key = None
        logging.debug("LAST BLOCK KEY : %s", last_block_key)

        if last_block_key:
            # DB에서 마지막 블럭을 가져와서 last_block 에 바인딩
            self.__last_block = Block(channel_name=self.__channel_name)
            block_dump = self.__confirmed_block_db.Get(last_block_key)
            self.__last_block.deserialize_block(block_dump)
            logging.debug("restore from last block hash(" + str(self.__last_block.block_hash) + ")")
            logging.debug("restore from last block height(" + str(self.__last_block.height) + ")")

        # 블럭의 높이는 마지막 블럭의 높이와 같음
        if self.__last_block is None:
            self.__block_height = -1
        else:
            self.__block_height = self.__last_block.height
        logging.debug(f"ENGINE-303 init_block_chain: {self.__block_height}")

    def generate_genesis_block(self):
        tx_info = None
        nid = NID.unknown.value
        if "genesis_data_path" in conf.CHANNEL_OPTION[self.__channel_name]:
            genesis_data_path = conf.CHANNEL_OPTION[self.__channel_name]["genesis_data_path"]
            util.logger.spam(f"Try to load a file of initial genesis block from ({genesis_data_path})")
            try:
                with open(genesis_data_path, encoding="utf-8") as json_file:
                    tx_info = json.load(json_file)["transaction_data"]
                    nid = tx_info["nid"]
                    # util.logger.spam(f"generate_genesis_block::tx_info >>>> {tx_info}")

            except FileNotFoundError as e:
                exit(f"cannot open json file in ({genesis_data_path}): {e}")
            except KeyError as e:
                exit(f"cannot find key name of {e} in genesis data file.")

        self.__add_genesisblock(tx_info)
        self.put_nid(nid)
        ChannelProperty().nid = nid

        util.logger.spam(f"add_genesisblock({self.__channel_name}/nid({nid}))")

    def set_invoke_results(self, block_hash, invoke_results):
        self.__invoke_results[block_hash] = invoke_results

    def set_last_commit_state(self, height, commit_state):
        self.last_commit_state_height = height
        self.last_commit_state = copy.deepcopy(commit_state)

    def invoke_for_precommit(self, precommit_block: Block):
        invoke_results = \
            self.__score_invoke_with_state_integrity(precommit_block, precommit_block.commit_state)
        self.__add_tx_to_block_db(precommit_block, invoke_results)
