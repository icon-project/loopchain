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
import json
import leveldb
import pickle
import threading
import zlib
from enum import Enum
from typing import Union, List

import loopchain.utils as util
from loopchain import configure as conf
from loopchain.baseservice import ScoreResponse, ObjectManager
from loopchain.blockchain import (Block, BlockBuilder, BlockSerializer, BlockProver, BlockProverType, BlockVersioner,
                                  Transaction, TransactionBuilder, TransactionSerializer,
                                  Hash32, ExternalAddress, TransactionVersioner, TransactionStatusInQueue)
from loopchain.blockchain.exception import *
from loopchain.blockchain.score_base import *
from loopchain.channel.channel_property import ChannelProperty
from loopchain.utils.message_queue import StubCollection


class NID(Enum):
    mainnet = "0x1"
    testnet = "0x2"
    unknown = "0x3"


class BlockChain:
    """Block chain with only committed blocks."""

    NID_KEY = b'NID_KEY'
    PRECOMMIT_BLOCK_KEY = b'PRECOMMIT_BLOCK'
    TRANSACTION_COUNT_KEY = b'TRANSACTION_COUNT'
    LAST_BLOCK_KEY = b'last_block_key'
    BLOCK_HEIGHT_KEY = b'block_height_key'

    # Additional information of the block is generated when the add_block phase of the consensus is reached.
    CONFIRM_INFO_KEY = b'confirm_info_key'
    INVOKE_RESULT_BLOCK_HEIGHT_KEY = b'invoke_result_block_height_key'

    def __init__(self, blockchain_db=None, channel_name=None):
        if channel_name is None:
            channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL

        self.__block_height = -1
        # last block in block db
        self.__last_block = None
        # last unconfirmed block that the leader broadcast.
        self.last_unconfirmed_block = None
        self.__channel_name = channel_name
        self.__peer_id = ChannelProperty().peer_id

        # block db has [ block_hash - block | block_height - block_hash | BlockChain.LAST_BLOCK_KEY - block_hash ]
        self.__confirmed_block_db = blockchain_db
        # logging.debug(f"BlockChain::init confirmed_block_db({self.__confirmed_block_db})")

        if self.__confirmed_block_db is None:
            try:
                self.__confirmed_block_db = leveldb.LevelDB(conf.DEFAULT_LEVEL_DB_PATH)
            except leveldb.LevelDBError:
                raise leveldb.LevelDBError("Fail To Create Level DB(path): " + conf.DEFAULT_LEVEL_DB_PATH)

        # made block count as a leader
        self.__invoke_results = {}

        self.__add_block_lock = threading.RLock()
        self.__confirmed_block_lock = threading.RLock()

        self.__total_tx = 0
        self.__nid: str = None

        channel_option = conf.CHANNEL_OPTION[channel_name]

        self.__block_versioner = BlockVersioner()
        for version, height in channel_option.get("block_versions", {}).items():
            self.__block_versioner.add_version(height, version)

        self.__tx_versioner = TransactionVersioner()
        for tx_version, tx_hash_version in channel_option.get("hash_versions", {}).items():
            self.__tx_versioner.hash_generator_versions[tx_version] = tx_hash_version

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
        return self.__last_block

    @property
    def block_versioner(self):
        return self.__block_versioner

    @property
    def tx_versioner(self):
        return self.__tx_versioner

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
            logging.info(f"block hash({self.__last_block.header.hash.hex()}) and height({self.__last_block.header.height})")
            return True
        else:
            logging.info("There is no block.")
            return False

    def _rebuild_transaction_count_from_blocks(self):
        total_tx = 0
        block_hash = self.__last_block.header.hash.hex()
        block_height = self.__last_block.header.height

        while block_hash != "":
            block_dump = self.__confirmed_block_db.Get(block_hash.encode(encoding='UTF-8'))
            block_version = self.__block_versioner.get_version(block_height)
            block_serializer = BlockSerializer.new(block_version, self.tx_versioner)
            block = block_serializer.deserialize(json.loads(block_dump))

            # Count only normal block`s tx count, not genesis block`s
            if block.header.height > 0:
                total_tx += len(block.body.transactions)

            # next loop
            block_height = block.header.height - 1
            block_hash = block.header.prev_hash.hex()
        return total_tx

    def _rebuild_transaction_count_from_cached(self):
        tx_count_bytes = self.__confirmed_block_db.Get(BlockChain.TRANSACTION_COUNT_KEY)
        return int.from_bytes(tx_count_bytes, byteorder='big')

    def __find_block_by_key(self, key):
        try:
            block_bytes = self.__confirmed_block_db.Get(key)
            block_dumped = json.loads(block_bytes)
            block_height = self.__block_versioner.get_height(block_dumped)
            block_version = self.__block_versioner.get_version(block_height)
            return BlockSerializer.new(block_version, self.tx_versioner).deserialize(block_dumped)
        except KeyError as e:
            logging.error(f"__find_block_by_key::KeyError block_hash({key}) error({e})")

        return None

    def find_block_by_hash(self, block_hash: Union[str, Hash32]):
        """find block by block hash.

        :param block_hash: plain string,
        key 로 사용되기전에 함수내에서 encoding 되므로 미리 encoding 된 key를 parameter 로 사용해선 안된다.
        :return: None or Block
        """
        if isinstance(block_hash, Hash32):
            block_hash = block_hash.hex()
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
            if self.last_unconfirmed_block:
                if self.last_unconfirmed_block.header.height == block_height:
                    return self.last_unconfirmed_block
            return None

        return self.__find_block_by_key(key)

    def find_confirm_info_by_hash(self, hash) -> bytearray:
        hash_encoded = hash.hex().encode(encoding='UTF-8')

        try:
            return self.__confirmed_block_db.Get(BlockChain.CONFIRM_INFO_KEY + hash_encoded)
        except KeyError:
            return bytearray(b"")

    def find_confirm_info_by_height(self, height) -> bytearray:
        block = self.find_block_by_height(height)
        if block:
            return self.find_confirm_info_by_hash(block.header.hash)

        return bytearray(b"")

    # TODO The current Citizen node sync by announce_confirmed_block message.
    #  However, this message does not include voting.
    #  You need to change it and remove the default None parameter here.
    def add_block(self, block: Block, confirm_info=None) -> bool:
        """

        :param block:
        :param confirm_info: additional info for this block, but It came from next block of this block.
        :return:
        """
        with self.__add_block_lock:
            if not self.prevent_next_block_mismatch(block.header.height):
                return True

            peer_id = ChannelProperty().peer_id
            util.apm_event(peer_id, {
                'event_type': 'TotalTx',
                'peer_id': peer_id,
                'peer_name': conf.PEER_NAME,
                'channel_name': self.__channel_name,
                'data': {
                    'block_hash': block.header.hash.hex(),
                    'total_tx': self.total_tx}})

            return self.__add_block(block, confirm_info)

    def __add_block(self, block: Block, confirm_info):
        with self.__add_block_lock:
            invoke_results = self.__invoke_results.get(block.header.hash.hex(), None)
            if invoke_results is None:
                if block.header.height == 0:
                    block, invoke_results = ObjectManager().channel_service.genesis_invoke(block)
                else:
                    block, invoke_results = ObjectManager().channel_service.score_invoke(block)

            try:
                self.__add_tx_to_block_db(block, invoke_results)
                ObjectManager().channel_service.score_write_precommit_state(block)
            except Exception as e:
                logging.warning(f"blockchain:add_block FAIL "
                                f"channel_service.score_write_precommit_state")
                raise e
            finally:
                self.__invoke_results.pop(block.header.hash.hex(), None)

            next_total_tx = self.__write_block_data(block, confirm_info)

            self.__last_block = block
            self.__block_height = self.__last_block.header.height
            self.__total_tx = next_total_tx
            logging.debug(f"blockchain add_block set block_height({self.__block_height}), "
                          f"last_block({self.__last_block.header.hash.hex()})")
            logging.info(
                f"ADD BLOCK HEIGHT : {block.header.height} , "
                f"HASH : {block.header.hash.hex()} , "
                f"CHANNEL : {self.__channel_name}")
            logging.debug(f"ADDED BLOCK HEADER : {block.header}")

            util.apm_event(self.__peer_id, {
                'event_type': 'AddBlock',
                'peer_id': self.__peer_id,
                'peer_name': conf.PEER_NAME,
                'channel_name': self.__channel_name,
                'data': {
                    'block_height': self.__block_height
                }})

            # notify new block
            ObjectManager().channel_service.inner_service.notify_new_block()

            return True

    def __write_block_data(self, block: Block, confirm_info):
        # a condition for the exception case of genesis block.
        next_total_tx = self.__total_tx
        if block.header.height > 0:
            next_total_tx += len(block.body.transactions)

        bit_length = next_total_tx.bit_length()
        byte_length = (bit_length + 7) // 8
        next_total_tx_bytes = next_total_tx.to_bytes(byte_length, byteorder='big')

        block_serializer = BlockSerializer.new(block.header.version, self.tx_versioner)
        block_serialized = json.dumps(block_serializer.serialize(block))
        block_hash_encoded = block.header.hash.hex().encode(encoding='UTF-8')

        batch = leveldb.WriteBatch()
        batch.Put(block_hash_encoded, block_serialized.encode("utf-8"))
        batch.Put(BlockChain.LAST_BLOCK_KEY, block_hash_encoded)
        batch.Put(BlockChain.TRANSACTION_COUNT_KEY, next_total_tx_bytes)
        batch.Put(
            BlockChain.BLOCK_HEIGHT_KEY +
            block.header.height.to_bytes(conf.BLOCK_HEIGHT_BYTES_LEN, byteorder='big'),
            block_hash_encoded)

        if confirm_info:
            batch.Put(
                BlockChain.CONFIRM_INFO_KEY + block_hash_encoded,
                b'0x1'
            )

        self.__confirmed_block_db.Write(batch)

        return next_total_tx

    def prevent_next_block_mismatch(self, next_height: int) -> bool:
        logging.debug(f"prevent_block_mismatch...")
        score_stub = StubCollection().icon_score_stubs[self.__channel_name]
        request = {
            "method": "ise_getStatus",
            "params": {"filter": ["lastBlock"]}
        }

        response = score_stub.sync_task().query(request)
        score_last_block_height = int(response['lastBlock']['blockHeight'], 16)

        if score_last_block_height == next_height:
            logging.debug(f"already invoked block in score...")
            return False

        if score_last_block_height < next_height:
            for invoke_block_height in range(score_last_block_height + 1, next_height):
                logging.debug(f"mismatch invoke_block_height({invoke_block_height}) "
                              f"score_last_block_height({score_last_block_height}) "
                              f"next_block_height({next_height})")

                invoke_block = self.find_block_by_height(invoke_block_height)
                if invoke_block is None:
                    raise RuntimeError("Error raised during prevent mismatch block, "
                                       f"Cannot find block({invoke_block_height}")

                if invoke_block_height == 0:
                    invoke_block, invoke_block_result = ObjectManager().channel_service.genesis_invoke(invoke_block)
                else:
                    invoke_block, invoke_block_result = ObjectManager().channel_service.score_invoke(invoke_block)

                self.__add_tx_to_block_db(invoke_block, invoke_block_result)
                ObjectManager().channel_service.score_write_precommit_state(invoke_block)

            return True

        if score_last_block_height == next_height + 1:
            try:
                invoke_result_block_height_bytes = \
                    self.__confirmed_block_db.Get(BlockChain.INVOKE_RESULT_BLOCK_HEIGHT_KEY)
                invoke_result_block_height = int.from_bytes(invoke_result_block_height_bytes, byteorder='big')

                if invoke_result_block_height == next_height:
                    logging.debug("already saved invoke result...")
                    return False
            except KeyError:
                logging.debug("There is no invoke result height in db.")
        else:
            util.exit_and_msg("Too many different(over 2) of block height between the loopchain and score. "
                              "Peer will be down. : "
                              f"loopchain({next_height})/score({score_last_block_height})")
            return True

    def __add_tx_to_block_db(self, block, invoke_results):
        """block db 에 block_hash - block_object 를 저장할때, tx_hash - block_hash 를 저장한다.
        get tx by tx_hash 시 해당 block 을 효율적으로 찾기 위해서
        :param block:
        """
        # loop all tx in block
        logging.debug("try add all tx in block to block db, block hash: " + block.header.hash.hex())
        block_manager = ObjectManager().channel_service.block_manager
        tx_queue = block_manager.get_tx_queue()
        # util.logger.spam(f"blockchain:__add_tx_to_block_db::tx_queue : {tx_queue}")
        # util.logger.spam(
        #     f"blockchain:__add_tx_to_block_db::confirmed_transaction_list : {block.confirmed_transaction_list}")

        for index, tx in enumerate(block.body.transactions.values()):
            tx_hash = tx.hash.hex()
            invoke_result = invoke_results[tx_hash]

            tx_serializer = TransactionSerializer.new(tx.version, self.__tx_versioner)
            tx_info = {
                'block_hash': block.header.hash.hex(),
                'block_height': block.header.height,
                'tx_index': hex(index),
                'transaction': tx_serializer.to_db_data(tx),
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

            if block.header.height > 0:
                self.__save_tx_by_address(tx)

        self.__save_invoke_result_block_height(block.header.height)

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
        logging.debug("try to change status to precommit in queue, block hash: " + precommit_block.header.hash.hex())
        tx_queue = ObjectManager().channel_service.block_manager.get_tx_queue()
        # util.logger.spam(f"blockchain:__precommit_tx::tx_queue : {tx_queue}")

        for tx in precommit_block.body.transactions.values():
            tx_hash = tx.hash.hex()
            if tx_queue.get_item_in_status(TransactionStatusInQueue.normal, TransactionStatusInQueue.normal):
                try:
                    tx_queue.set_item_status(tx_hash, TransactionStatusInQueue.precommited_to_block)
                    # util.logger.spam(
                    #     f"blockchain:__precommit_tx::{tx_hash}'s status : {tx_queue.get_item_status(tx_hash)}")
                except KeyError as e:
                    logging.warning(f"blockchain:__precommit_tx::KeyError:There is no tx by hash({tx_hash})")

    def __save_tx_by_address(self, tx: 'Transaction'):
        address = tx.from_address.hex_hx()
        return self.add_tx_to_list_by_address(address, tx.hash.hex())

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
            if self.__nid is not None:
                return self.__nid

            nid = self.__confirmed_block_db.Get(BlockChain.NID_KEY)
            self.__nid = nid.decode(conf.HASH_KEY_ENCODING)
            return self.__nid
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
        """find tx by hash

        :param tx_hash_key: tx hash
        :return None: There is no tx by hash or transaction object.
        """

        try:
            tx_info_json = self.find_tx_info(tx_hash_key)
        except KeyError as e:
            # This case is not an error.
            # Client send wrong tx_hash..
            # logging.warning(f"[blockchain::find_tx_by_key] Transaction is pending. tx_hash ({tx_hash_key})")
            return None
        if tx_info_json is None:
            logging.warning(f"tx not found. tx_hash ({tx_hash_key})")
            return None

        tx_data = tx_info_json["transaction"]
        tx_version = self.tx_versioner.get_version(tx_data)
        tx_serializer = TransactionSerializer.new(tx_version, self.tx_versioner)
        return tx_serializer.from_(tx_data)

    def find_invoke_result_by_tx_hash(self, tx_hash: Union[str, Hash32]):
        """find invoke result matching tx_hash and return result if not in blockchain return code delay

        :param tx_hash: tx_hash
        :return: {"code" : "code", "error_message" : "error_message if not fail this is not exist"}
        """
        if isinstance(tx_hash, Hash32):
            tx_hash = tx_hash.hex()
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

    def find_tx_info(self, tx_hash_key: Union[str, Hash32]):
        if isinstance(tx_hash_key, Hash32):
            tx_hash_key = tx_hash_key.hex()

        try:
            tx_info = self.__confirmed_block_db.Get(
                tx_hash_key.encode(encoding=conf.HASH_KEY_ENCODING))
            tx_info_json = json.loads(tx_info, encoding=conf.PEER_DATA_ENCODING)

        except UnicodeDecodeError as e:
            logging.warning("blockchain::find_tx_info: UnicodeDecodeError: " + str(e))
            return None
        # except KeyError as e:
        #     logging.debug("blockchain::find_tx_info: not found tx: " + str(e))
        #     return None

        return tx_info_json

    def __add_genesis_block(self, tx_info: dict, reps: List[ExternalAddress]):
        """
        :param tx_info: Transaction data for making genesis block from an initial file
        :return:
        """
        logging.info("Make Genesis Block....")
        tx_builder = TransactionBuilder.new("genesis", self.tx_versioner)

        nid = tx_info.get("nid")
        if nid is not None:
            nid = int(nid, 16)
        tx_builder.nid = nid  # Optional. It will be 0x3 except for mainnet and testnet if not defined
        tx_builder.accounts = tx_info["accounts"]
        tx_builder.message = tx_info["message"]
        tx = tx_builder.build()

        block_version = self.block_versioner.get_version(0)
        block_builder = BlockBuilder.new(block_version, self.tx_versioner)
        block_builder.height = 0
        block_builder.fixed_timestamp = 0
        block_builder.prev_hash = None
        block_builder.next_leader = ExternalAddress.fromhex(self.__peer_id)
        block_builder.transactions[tx.hash] = tx
        block_builder.reps = reps
        block = block_builder.build()  # It does not have commit state. It will be rebuilt.

        block, invoke_results = ObjectManager().channel_service.genesis_invoke(block)
        self.set_invoke_results(block.header.hash.hex(), invoke_results)
        self.add_block(block)

    def put_precommit_block(self, precommit_block: Block):
        # write precommit block to DB
        logging.debug(
            f"blockchain:put_precommit_block ({self.__channel_name}), hash ({precommit_block.header.hash.hex()})")
        if self.__last_block.header.height < precommit_block.header.height:
            self.__precommit_tx(precommit_block)
            util.logger.spam(f"blockchain:put_precommit_block:confirmed_transaction_list")

            block_serializer = BlockSerializer.new(precommit_block.header.version, self.tx_versioner)
            block_serialized = block_serializer.serialize(precommit_block)
            block_serialized = json.dumps(block_serialized)
            block_serialized = block_serialized.encode('utf-8')
            results = self.__confirmed_block_db.Put(BlockChain.PRECOMMIT_BLOCK_KEY, block_serialized)

            util.logger.spam(f"result of to write to db ({results})")
            logging.info(f"ADD BLOCK PRECOMMIT HEIGHT : {precommit_block.header.height} , "
                         f"HASH : {precommit_block.header.hash.hex()}, CHANNEL : {self.__channel_name}")
        else:
            results = None
            logging.debug(f"blockchain:put_precommit_block::this precommit block is not validate. "
                          f"the height of precommit block must be bigger than the last block."
                          f"(last block:{self.__last_block.header.height}/"
                          f"precommit block:{precommit_block.header.height})")

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

    def confirm_prev_block(self, current_block: Block):
        """confirm prev unconfirmed block by votes in current block

        :param current_block: Next unconfirmed block what has votes for prev unconfirmed block.
        :return: confirm_Block
        """
        # util.logger.debug(f"-------------------confirm_prev_block---current_block is "
        #                    f"tx count({len(current_block.body.transactions)}), "
        #                    f"height({current_block.header.height})")

        candidate_blocks = ObjectManager().channel_service.block_manager.candidate_blocks
        with self.__confirmed_block_lock:
            logging.debug(f"BlockChain:confirm_block channel({self.__channel_name})")

            try:
                unconfirmed_block = candidate_blocks.blocks[current_block.header.prev_hash].block
                logging.debug("confirmed_block_hash: " + current_block.header.prev_hash.hex())
                if unconfirmed_block:
                    logging.debug("unconfirmed_block.block_hash: " + unconfirmed_block.header.hash.hex())
                    logging.debug("unconfirmed_block.prev_block_hash: " + unconfirmed_block.header.prev_hash.hex())
                else:
                    logging.warning("There is no unconfirmed_block in candidate_blocks")
                    return None

            except KeyError:
                if self.last_block.header.hash == current_block.header.prev_hash:
                    logging.warning(f"Already added block hash({current_block.header.prev_hash.hex()})")
                    if current_block.header.complained:
                        util.logger.debug("reset last_unconfirmed_block by complain block")
                        self.last_unconfirmed_block = current_block
                    return None
                else:
                    except_msg = ("there is no unconfirmed block in this peer "
                                  f"block_hash({current_block.header.prev_hash.hex()})")
                    logging.warning(except_msg)
                    raise BlockchainError(except_msg)

            if unconfirmed_block.header.hash != current_block.header.prev_hash:
                logging.warning("It's not possible to add block while check block hash is fail-")
                raise BlockchainError('확인하는 블럭 해쉬 값이 다릅니다.')

            # util.logger.debug(f"-------------------confirm_prev_block---before add block,"
            #                    f"height({unconfirmed_block.header.height})")
            self.add_block(unconfirmed_block, current_block.body.confirm_prev_block)
            self.last_unconfirmed_block = current_block
            candidate_blocks.remove_block(current_block.header.prev_hash)

            return unconfirmed_block

    def init_blockchain(self):
        # level DB에서 블럭을 읽어 들이며, 만약 levelDB에 블럭이 없을 경우 제네시스 블럭을 만든다
        try:
            last_block_key = self.__confirmed_block_db.Get(BlockChain.LAST_BLOCK_KEY, True)
        except KeyError:
            last_block_key = None
        logging.debug("LAST BLOCK KEY : %s", last_block_key)

        if last_block_key:
            block_dump = self.__confirmed_block_db.Get(last_block_key)
            block_dump = json.loads(block_dump)
            block_height = self.__block_versioner.get_height(block_dump)
            block_version = self.__block_versioner.get_version(block_height)
            self.__last_block = BlockSerializer.new(block_version, self.tx_versioner).deserialize(block_dump)

            logging.debug("restore from last block hash(" + str(self.__last_block.header.hash.hex()) + ")")
            logging.debug("restore from last block height(" + str(self.__last_block.header.height) + ")")

        # 블럭의 높이는 마지막 블럭의 높이와 같음
        if self.__last_block is None:
            self.__block_height = -1
        else:
            self.__block_height = self.__last_block.header.height
        logging.debug(f"ENGINE-303 init_blockchain: {self.__block_height}")

    def generate_genesis_block(self, reps: List[ExternalAddress]):
        tx_info = None
        nid = NID.unknown.value
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

        self.__add_genesis_block(tx_info, reps)
        self.put_nid(nid)
        ChannelProperty().nid = nid

        util.logger.spam(f"add_genesis_block({self.__channel_name}/nid({nid}))")

    def set_invoke_results(self, block_hash, invoke_results):
        self.__invoke_results[block_hash] = invoke_results

    def invoke_for_precommit(self, precommit_block: Block):
        invoke_results = \
            self.__score_invoke_with_state_integrity(precommit_block, precommit_block.commit_state)
        self.__add_tx_to_block_db(precommit_block, invoke_results)

    def block_dumps(self, block: Block) -> bytes:
        block_version = self.__block_versioner.get_version(block.header.height)
        block_serializer = BlockSerializer.new(block_version, self.tx_versioner)
        block_serialized = block_serializer.serialize(block)

        """
        FIXME: this is a workaround. confirm_prev_block is used temporarily. We will remove the attribute.
        If confirm_prev_block is serialized in serialize() function, it will be put in DB but we don't want it.
        """
        if hasattr(block.body, 'confirm_prev_block'):
            block_serialized['confirm_prev_block'] = block.body.confirm_prev_block

        block_json = json.dumps(block_serialized)
        block_dumped = block_json.encode(encoding=conf.PEER_DATA_ENCODING)
        block_dumped = zlib.compress(block_dumped)
        return block_dumped

    def block_loads(self, block_dumped: bytes) -> Block:
        block_dumped = zlib.decompress(block_dumped)
        block_json = block_dumped.decode(encoding=conf.PEER_DATA_ENCODING)
        block_serialized = json.loads(block_json)
        block_height = self.__block_versioner.get_height(block_serialized)
        block_version = self.__block_versioner.get_version(block_height)
        block_serializer = BlockSerializer.new(block_version, self.tx_versioner)
        return block_serializer.deserialize(block_serialized)

    def get_transaction_proof(self, tx_hash: Hash32):
        try:
            tx_info = self.find_tx_info(tx_hash.hex())
        except KeyError:
            raise RuntimeError(f"Tx does not exist.")

        block_hash = tx_info["block_hash"]
        block = self.find_block_by_hash(block_hash)

        if block.header.version == "0.1a":
            raise RuntimeError(f"Block version({block.header.version}) of the Tx does not support proof.")

        block_prover = BlockProver.new(block.header.version, block.body.transactions, BlockProverType.Transaction)
        return block_prover.get_proof(tx_hash)

    def prove_transaction(self, tx_hash: Hash32, proof: list):
        try:
            tx_info = self.find_tx_info(tx_hash.hex())
        except KeyError:
            raise RuntimeError(f"Tx does not exist.")

        block_hash = tx_info["block_hash"]
        block = self.find_block_by_hash(block_hash)

        if block.header.version == "0.1a":
            raise RuntimeError(f"Block version({block.header.version}) of the Tx does not support proof.")

        block_prover = BlockProver.new(block.header.version, None, BlockProverType.Transaction)  # Do not need txs
        return block_prover.prove(tx_hash, block.header.transaction_hash, proof)

    def get_receipt_proof(self, tx_hash: Hash32):
        try:
            tx_info = self.find_tx_info(tx_hash.hex())
        except KeyError:
            raise RuntimeError(f"Tx does not exist.")
        tx_result = tx_info["result"]

        block_hash = tx_info["block_hash"]
        block = self.find_block_by_hash(block_hash)

        if block.header.version == "0.1a":
            raise RuntimeError(f"Block version({block.header.version}) of the Tx does not support proof.")

        tx_results = (self.find_tx_info(tx_hash)["result"] for tx_hash in block.body.transactions)
        block_prover = BlockProver.new(block.header.version, tx_results, BlockProverType.Receipt)
        receipt_hash = block_prover.to_hash32(tx_result)
        return block_prover.get_proof(receipt_hash)

    def prove_receipt(self, tx_hash: Hash32, proof: list):
        try:
            tx_info = self.find_tx_info(tx_hash.hex())
        except KeyError:
            raise RuntimeError(f"Tx does not exist.")
        tx_result = tx_info["result"]

        block_hash = tx_info["block_hash"]
        block = self.find_block_by_hash(block_hash)

        if block.header.version == "0.1a":
            raise RuntimeError(f"Block version({block.header.version}) of the Tx does not support proof.")

        block_prover = BlockProver.new(block.header.version, None, BlockProverType.Receipt)    # Do not need receipts
        receipt_hash = block_prover.to_hash32(tx_result)
        return block_prover.prove(receipt_hash, block.header.receipt_hash, proof)
