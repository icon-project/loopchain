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
import pickle
import threading
import zlib
from collections import Counter
from enum import Enum
from os import linesep
from typing import Union, List, cast, Optional

from loopchain import configure as conf
from loopchain import utils
from loopchain.baseservice import ScoreResponse, ObjectManager
from loopchain.baseservice.aging_cache import AgingCache
from loopchain.blockchain.blocks import Block, BlockBuilder, BlockSerializer
from loopchain.blockchain.blocks import BlockProver, BlockProverType, BlockVersioner
from loopchain.blockchain.exception import *
from loopchain.blockchain.score_base import *
from loopchain.blockchain.transactions import Transaction, TransactionBuilder
from loopchain.blockchain.transactions import TransactionSerializer, TransactionVersioner
from loopchain.blockchain.types import Hash32, ExternalAddress, TransactionStatusInQueue
from loopchain.blockchain.votes.v0_1a import BlockVotes
from loopchain.channel.channel_property import ChannelProperty
from loopchain.store.key_value_store import KeyValueStore, KeyValueStoreWriteBatch
from loopchain.utils.icon_service import convert_params, ParamType, response_to_json_query
from loopchain.utils.message_queue import StubCollection

if TYPE_CHECKING:
    from loopchain.peer import BlockManager

__all__ = ("NID", "BlockChain")


class NID(Enum):
    mainnet = "0x1"
    testnet = "0x2"
    unknown = "0x3"


class MadeBlockCounter(Counter):
    def __str__(self):
        return linesep.join(f"{k}: {v}" for k, v in self.items())


class BlockChain:
    """Block chain with only committed blocks."""

    NID_KEY = b'NID_KEY'
    PRECOMMIT_BLOCK_KEY = b'PRECOMMIT_BLOCK'
    TRANSACTION_COUNT_KEY = b'TRANSACTION_COUNT'
    LAST_BLOCK_KEY = b'last_block_key'
    BLOCK_HEIGHT_KEY = b'block_height_key'

    # Additional information of the block is generated when the add_block phase of the consensus is reached.
    CONFIRM_INFO_KEY = b'confirm_info_key'
    PREPS_KEY = b'preps_key'
    INVOKE_RESULT_BLOCK_HEIGHT_KEY = b'invoke_result_block_height_key'

    def __init__(self, channel_name=None, peer_id=None, peer_address=None, store_id=None, block_manager=None):
        if channel_name is None:
            channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL

        self.__block_height = -1
        # last block in block db
        self.__last_block = None
        self.__made_block_counter = MadeBlockCounter()

        # last unconfirmed block that the leader broadcast.
        self.last_unconfirmed_block = None
        self.__channel_name = channel_name
        self.__peer_id = peer_id
        self.__peer_address = peer_address
        self.__block_manager: BlockManager = block_manager

        store_id = f"{store_id}_{channel_name}"
        self._blockchain_store, self._blockchain_store_path = utils.init_default_key_value_store(store_id)

        # tx receipts and next prep after invoke, {Hash32: (receipts, next_prep)}
        self.__invoke_results: AgingCache = AgingCache(max_age_seconds=conf.INVOKE_RESULT_AGING_SECONDS)

        self.__add_block_lock = threading.RLock()
        self.__confirmed_block_lock = threading.RLock()

        self.__total_tx = 0
        self.__nid: Optional[str] = None

        channel_option = conf.CHANNEL_OPTION[channel_name]

        self.__block_versioner = BlockVersioner()
        for version, height in channel_option.get("block_versions", {}).items():
            self.__block_versioner.add_version(height, version)

        self.__tx_versioner = TransactionVersioner()
        for tx_version, tx_hash_version in channel_option.get("hash_versions", {}).items():
            self.__tx_versioner.hash_generator_versions[tx_version] = tx_hash_version

    @property
    def leader_made_block_count(self) -> int:
        if self.__last_block:
            return self.__made_block_counter[self.__last_block.header.peer_id]
        return -1

    @property
    def my_made_block_count(self) -> int:
        return self.__made_block_counter[self.__peer_address]

    def _increase_made_block_count(self, block: Block) -> None:
        """This is must called before changing self.__last_block!

        :param block:
        :return:
        """
        if block.header.height == 0:
            return

        if self.__last_block.header.peer_id != block.header.peer_id:
            self.__made_block_counter[block.header.peer_id] = 1
        else:
            self.__made_block_counter[block.header.peer_id] += 1

        utils.logger.spam(f"({block.header.height})made_block_count:\n{self.__made_block_counter}")

    def reset_leader_made_block_count(self):
        self.__made_block_counter.clear()

    def get_next_leader(self) -> str:
        """get next leader by leader_made_block_count

        :return: new leader's peer_id as hex_hx(str)
        """

        peer_manager = ObjectManager().channel_service.peer_manager
        if self.leader_made_block_count == (conf.MAX_MADE_BLOCK_COUNT - 1):
            # (conf.MAX_MADE_BLOCK_COUNT - 1) means if made_block_count is 9,
            # next unconfirmed block height is 10 and It has to have changed next leader.
            return peer_manager.get_next_leader_peer(self.__last_block.header.peer_id.hex_hx()).peer_id

        return peer_manager.leader_id

    def get_expected_generator(self, peer_id: ExternalAddress) -> str:
        """get expected generator to vote unconfirmed block

        :return: expected generator's id by made block count.
        """

        peer_manager = ObjectManager().channel_service.peer_manager
        if self.__made_block_counter[peer_id] > conf.MAX_MADE_BLOCK_COUNT:
            return peer_manager.get_next_leader_peer(peer_id).peer_id
        return peer_id.hex_hx()

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

    @property
    def peer_id(self):
        return self.__peer_id

    @property
    def peer_address(self):
        return self.__peer_address

    def get_blockchain_store(self):
        return self._blockchain_store

    def close_blockchain_store(self):
        print(f"close blockchain_store = {self._blockchain_store}")
        if self._blockchain_store:
            self._blockchain_store.close()
            self._blockchain_store: KeyValueStore = None

    def rebuild_made_block_count(self):
        """rebuild leader's made block count

        :return:
        """
        self.reset_leader_made_block_count()

        block_hash = self.__last_block.header.hash.hex()
        block_height = self.__last_block.header.height
        start_block_height = self.__last_block.header.height

        while block_hash != "":
            if block_height <= 0:
                return

            block_dump = self._blockchain_store.get(block_hash.encode(encoding='UTF-8'))
            block_version = self.__block_versioner.get_version(block_height)
            block_serializer = BlockSerializer.new(block_version, self.__tx_versioner)
            block = block_serializer.deserialize(json.loads(block_dump))

            self.__made_block_counter[block.header.peer_id] += 1

            if start_block_height - block.header.height >= conf.MAX_MADE_BLOCK_COUNT:
                break

            # next loop
            block_height = block.header.height - 1
            block_hash = block.header.prev_hash.hex()

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
            logging.info(
                f"block hash({self.__last_block.header.hash.hex()})"
                f" and height({self.__last_block.header.height})")
            return True
        else:
            logging.info("There is no block.")
            return False

    def _rebuild_transaction_count_from_blocks(self):
        total_tx = 0
        block_hash = self.__last_block.header.hash.hex()
        block_height = self.__last_block.header.height

        while block_hash != "":
            block_dump = self._blockchain_store.get(block_hash.encode(encoding='UTF-8'))
            block_version = self.__block_versioner.get_version(block_height)
            block_serializer = BlockSerializer.new(block_version, self.__tx_versioner)
            block = block_serializer.deserialize(json.loads(block_dump))

            # Count only normal block`s tx count, not genesis block`s
            if block.header.height > 0:
                total_tx += len(block.body.transactions)

            # next loop
            block_height = block.header.height - 1
            block_hash = block.header.prev_hash.hex()
        return total_tx

    def _rebuild_transaction_count_from_cached(self):
        tx_count_bytes = self._blockchain_store.get(BlockChain.TRANSACTION_COUNT_KEY)
        return int.from_bytes(tx_count_bytes, byteorder='big')

    def __find_block_by_key(self, key):
        try:
            block_bytes = self._blockchain_store.get(key)
            block_dumped = json.loads(block_bytes)
            block_height = self.__block_versioner.get_height(block_dumped)
            block_version = self.__block_versioner.get_version(block_height)
            return BlockSerializer.new(block_version, self.__tx_versioner).deserialize(block_dumped)
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
            key = self._blockchain_store.get(BlockChain.BLOCK_HEIGHT_KEY +
                                             block_height.to_bytes(conf.BLOCK_HEIGHT_BYTES_LEN, byteorder='big'))
        except KeyError:
            if self.last_unconfirmed_block:
                if self.last_unconfirmed_block.header.height == block_height:
                    return self.last_unconfirmed_block
            return None

        return self.__find_block_by_key(key)

    def find_confirm_info_by_hash(self, block_hash) -> bytes:
        hash_encoded = block_hash.hex().encode(encoding='UTF-8')

        try:
            return bytes(self._blockchain_store.get(BlockChain.CONFIRM_INFO_KEY + hash_encoded))
        except KeyError:
            return bytes()

    def find_confirm_info_by_height(self, height) -> bytes:
        block = self.find_block_by_height(height)
        if block:
            return bytes(self.find_confirm_info_by_hash(block.header.hash))

        return bytes()

    def find_preps_ids_by_roothash(self, roothash: Hash32) -> List[str]:
        preps = self.find_preps_by_roothash(roothash)
        return [prep["id"] for prep in preps]

    def find_preps_addresses_by_roothash(self, roothash: Hash32) -> List[ExternalAddress]:
        preps_ids = self.find_preps_ids_by_roothash(roothash)
        return [ExternalAddress.fromhex(prep_id) for prep_id in preps_ids]

    def find_preps_by_roothash(self, roothash: Hash32) -> list:
        try:
            preps_dumped = bytes(self._blockchain_store.get(BlockChain.PREPS_KEY + roothash))
        except KeyError:
            return []
        else:
            return json.loads(preps_dumped)

    def write_preps(self, roothash: Hash32, preps: list, batch: KeyValueStoreWriteBatch = None):
        write_target = batch or self._blockchain_store

        write_target.put(
            BlockChain.PREPS_KEY + roothash,
            json.dumps(preps).encode(encoding=conf.PEER_DATA_ENCODING)
        )

    # TODO The current Citizen node sync by announce_confirmed_block message.
    #  However, this message does not include voting.
    #  You need to change it and remove the default None parameter here.
    def add_block(self,
                  block: Block,
                  confirm_info=None,
                  need_to_write_tx_info=True,
                  need_to_score_invoke=True) -> bool:
        """

        :param block:
        :param confirm_info: additional info for this block, but It came from next block of this block.
        :param need_to_write_tx_info:
        :param need_to_score_invoke:
        :return:
        """
        with self.__add_block_lock:
            if need_to_write_tx_info and need_to_score_invoke and \
                    not self.prevent_next_block_mismatch(block.header.height):
                return True

            peer_id = self.__peer_id
            utils.apm_event(peer_id, {
                'event_type': 'TotalTx',
                'peer_id': peer_id,
                'peer_name': conf.PEER_NAME,
                'channel_name': self.__channel_name,
                'data': {
                    'block_hash': block.header.hash.hex(),
                    'total_tx': self.total_tx}})

            return self.__add_block(block, confirm_info, need_to_write_tx_info, need_to_score_invoke)

    def __add_block(self, block: Block, confirm_info, need_to_write_tx_info=True, need_to_score_invoke=True):
        with self.__add_block_lock:
            receipts, next_prep = self.__invoke_results.get(block.header.hash, (None, None))
            if receipts is None and need_to_score_invoke:
                self.get_invoke_func(block.header.height)(block, self.__last_block)

            if not need_to_write_tx_info:
                receipts = None
            next_total_tx = self.__write_block_data(block, confirm_info, receipts, next_prep)

            try:
                if need_to_score_invoke:
                    ObjectManager().channel_service.score_write_precommit_state(block)
            except Exception as e:
                utils.exit_and_msg(f"score_write_precommit_state FAIL {e}")

            self.__invoke_results.pop(block.header.hash, None)

            self._increase_made_block_count(block)

            self.__last_block = block
            self.__block_height = self.__last_block.header.height
            self.__total_tx = next_total_tx

            logging.info(
                f"ADD BLOCK HEIGHT : {block.header.height} , "
                f"HASH : {block.header.hash.hex()} , "
                f"CHANNEL : {self.__channel_name}")
            utils.logger.debug(f"ADDED BLOCK HEADER : {block.header}")

            utils.apm_event(self.__peer_id, {
                'event_type': 'AddBlock',
                'peer_id': self.__peer_id,
                'peer_name': conf.PEER_NAME,
                'channel_name': self.__channel_name,
                'data': {
                    'block_height': self.__block_height
                }})

            # notify new block
            ObjectManager().channel_service.inner_service.notify_new_block()
            # reset_network_by_block_height is called in critical section by self.__add_block_lock.
            # Other Blocks must not be added until reset_network_by_block_height function finishes.
            ObjectManager().channel_service.switch_role()

            return True

    def _write_tx(self, block, receipts, batch=None):
        """save additional information of transactions to efficient searching and support user APIs.

        :param block:
        :param receipts: invoke result of transaction
        :param batch:
        :return:
        """
        write_target = batch or self._blockchain_store

        # loop all tx in block
        logging.debug("try add all tx in block to block db, block hash: " + block.header.hash.hex())
        tx_queue = self.__block_manager.get_tx_queue()

        for index, tx in enumerate(block.body.transactions.values()):
            tx_hash = tx.hash.hex()
            receipt = receipts[tx_hash]

            tx_serializer = TransactionSerializer.new(tx.version, tx.type(), self.__tx_versioner)
            tx_info = {
                'block_hash': block.header.hash.hex(),
                'block_height': block.header.height,
                'tx_index': hex(index),
                'transaction': tx_serializer.to_db_data(tx),
                'result': receipt
            }

            write_target.put(
                tx_hash.encode(encoding=conf.HASH_KEY_ENCODING),
                json.dumps(tx_info).encode(encoding=conf.PEER_DATA_ENCODING))

            tx_queue.pop(tx_hash, None)

            if block.header.height > 0:
                self._write_tx_by_address(tx, batch)

        # save_invoke_result_block_height
        bit_length = block.header.height.bit_length()
        byte_length = (bit_length + 7) // 8
        block_height_bytes = block.header.height.to_bytes(byte_length, byteorder='big')
        write_target.put(
            BlockChain.INVOKE_RESULT_BLOCK_HEIGHT_KEY,
            block_height_bytes
        )

    def __write_block_data(self, block: Block, confirm_info, receipts, next_prep):
        # a condition for the exception case of genesis block.
        next_total_tx = self.__total_tx
        if block.header.height > 0:
            next_total_tx += len(block.body.transactions)

        bit_length = next_total_tx.bit_length()
        byte_length = (bit_length + 7) // 8
        next_total_tx_bytes = next_total_tx.to_bytes(byte_length, byteorder='big')

        block_serializer = BlockSerializer.new(block.header.version, self.__tx_versioner)
        block_serialized = json.dumps(block_serializer.serialize(block))
        block_hash_encoded = block.header.hash.hex().encode(encoding='UTF-8')

        batch = self._blockchain_store.WriteBatch()
        batch.put(block_hash_encoded, block_serialized.encode("utf-8"))
        batch.put(BlockChain.LAST_BLOCK_KEY, block_hash_encoded)
        batch.put(BlockChain.TRANSACTION_COUNT_KEY, next_total_tx_bytes)
        batch.put(
            BlockChain.BLOCK_HEIGHT_KEY +
            block.header.height.to_bytes(conf.BLOCK_HEIGHT_BYTES_LEN, byteorder='big'),
            block_hash_encoded)

        if receipts:
            self._write_tx(block, receipts, batch)

        if next_prep:
            utils.logger.spam(f"store next_prep in __write_block_data\nprep_hash({next_prep['rootHash']})"
                              f"\npreps({next_prep['preps']})")
            self.write_preps(Hash32.fromhex(next_prep['rootHash'], ignore_prefix=True), next_prep['preps'], batch)

        if confirm_info:
            batch.put(
                BlockChain.CONFIRM_INFO_KEY + block_hash_encoded,
                json.dumps(BlockVotes.serialize_votes(confirm_info)).encode("utf-8")
            )

        if block.header.prev_hash:
            prev_block_hash_encoded = block.header.prev_hash.hex().encode("utf-8")
            prev_block_confirm_info_key = BlockChain.CONFIRM_INFO_KEY + prev_block_hash_encoded
            batch.delete(prev_block_confirm_info_key)

        batch.write()

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

        if score_last_block_height < next_height:
            for invoke_block_height in range(score_last_block_height + 1, next_height):
                logging.debug(f"mismatch invoke_block_height({invoke_block_height}) "
                              f"score_last_block_height({score_last_block_height}) "
                              f"next_block_height({next_height})")

                invoke_block = self.find_block_by_height(invoke_block_height)
                if invoke_block is None:
                    raise RuntimeError("Error raised during prevent mismatch block, "
                                       f"Cannot find block({invoke_block_height}")
                if invoke_block.header.height > 0:
                    prev_invoke_block = self.find_block_by_height(invoke_block_height - 1)
                    if prev_invoke_block is None:
                        raise RuntimeError("Error raised during prevent mismatch block, "
                                           f"Cannot find prev_block({invoke_block_height - 1}")
                else:
                    prev_invoke_block = None

                invoke_block, receipts = \
                    self.get_invoke_func(invoke_block_height)(invoke_block, prev_invoke_block)

                self._write_tx(invoke_block, receipts)
                ObjectManager().channel_service.score_write_precommit_state(invoke_block)

            return True

        elif score_last_block_height == next_height:
            logging.debug(f"already invoked block in score...")
            return False

        elif score_last_block_height == next_height + 1:
            try:
                invoke_result_block_height_bytes = \
                    self._blockchain_store.get(BlockChain.INVOKE_RESULT_BLOCK_HEIGHT_KEY)
                invoke_result_block_height = int.from_bytes(invoke_result_block_height_bytes, byteorder='big')

                if invoke_result_block_height == next_height:
                    logging.debug("already saved invoke result...")
                    return False
            except KeyError:
                logging.debug("There is no invoke result height in db.")
        else:
            # score_last_block_height is two or more higher than loopchain_last_block_height.
            utils.exit_and_msg("Too many different(over 2) of block height between the loopchain and score. "
                               "Peer will be down. : "
                               f"loopchain({next_height})/score({score_last_block_height})")
            return True

    def __precommit_tx(self, precommit_block):
        """ change status of transactions in a precommit block
        :param block:
        """
        # loop all tx in block
        logging.debug("try to change status to precommit in queue, block hash: " + precommit_block.header.hash.hex())
        tx_queue = self.__block_manager.get_tx_queue()
        # utils.logger.spam(f"blockchain:__precommit_tx::tx_queue : {tx_queue}")

        for tx in precommit_block.body.transactions.values():
            tx_hash = tx.hash.hex()
            if tx_queue.get_item_in_status(TransactionStatusInQueue.normal, TransactionStatusInQueue.normal):
                try:
                    tx_queue.set_item_status(tx_hash, TransactionStatusInQueue.precommited_to_block)
                    # utils.logger.spam(
                    #     f"blockchain:__precommit_tx::{tx_hash}'s status : {tx_queue.get_item_status(tx_hash)}")
                except KeyError as e:
                    logging.warning(f"blockchain:__precommit_tx::KeyError:There is no tx by hash({tx_hash})")

    def _write_tx_by_address(self, tx: 'Transaction', batch):
        if tx.type() == "base":
            return
        address = tx.from_address.hex_hx()
        return self.add_tx_to_list_by_address(address, tx.hash.hex(), batch)

    @staticmethod
    def __get_tx_list_key(address, index):
        return conf.TX_LIST_ADDRESS_PREFIX + (address + str(index)).encode(encoding=conf.HASH_KEY_ENCODING)

    def get_tx_list_by_address(self, address, index=0):
        list_key = self.__get_tx_list_key(address, index)

        try:
            tx_list = pickle.loads(self._blockchain_store.get(list_key))
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

            nid = self._blockchain_store.get(BlockChain.NID_KEY)
            self.__nid = nid.decode(conf.HASH_KEY_ENCODING)
            return self.__nid
        except KeyError as e:
            logging.debug(f"blockchain:get_nid::There is no NID.")
            return None

    def add_tx_to_list_by_address(self, address, tx_hash, batch=None):
        write_target = batch or self._blockchain_store
        current_list, current_index = self.get_tx_list_by_address(address, 0)

        if len(current_list) > conf.MAX_TX_LIST_SIZE_BY_ADDRESS:
            new_index = current_index + 1
            new_list_key = self.__get_tx_list_key(address, new_index)
            self._blockchain_store.put(new_list_key, pickle.dumps(current_list))
            current_list = [new_index]

        current_list.insert(0, tx_hash)
        list_key = self.__get_tx_list_key(address, 0)
        write_target.put(list_key, pickle.dumps(current_list))

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
        tx_version, tx_type = self.__tx_versioner.get_version(tx_data)
        tx_serializer = TransactionSerializer.new(tx_version, tx_type, self.__tx_versioner)
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
            if tx_hash in self.__block_manager.get_tx_queue():
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
            tx_info = self._blockchain_store.get(
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
        tx_builder = TransactionBuilder.new("genesis", "", self.__tx_versioner)

        nid = tx_info.get("nid")
        if nid is not None:
            nid = int(nid, 16)
        tx_builder.nid = nid  # Optional. It will be 0x3 except for mainnet and testnet if not defined
        tx_builder.accounts = tx_info["accounts"]
        tx_builder.message = tx_info["message"]
        tx = tx_builder.build(False)

        block_version = self.block_versioner.get_version(0)
        block_builder = BlockBuilder.new(block_version, self.__tx_versioner)
        block_builder.height = 0
        block_builder.fixed_timestamp = utils.get_now_time_stamp()
        block_builder.next_leader = ExternalAddress.fromhex(self.__peer_id)
        block_builder.transactions[tx.hash] = tx
        block_builder.reps = reps
        block_builder.prev_hash = Hash32.new()
        block_builder.signer = ChannelProperty().peer_auth
        block_builder.prev_votes = []
        block_builder.leader_votes = []
        block = block_builder.build()  # It does not have commit state. It will be rebuilt.

        block, invoke_results = self.genesis_invoke(block)
        self.add_block(block)

    def put_precommit_block(self, precommit_block: Block):
        # write precommit block to DB
        logging.debug(
            f"blockchain:put_precommit_block ({self.__channel_name}), hash ({precommit_block.header.hash.hex()})")
        if self.__last_block.header.height < precommit_block.header.height:
            self.__precommit_tx(precommit_block)
            utils.logger.spam(f"blockchain:put_precommit_block:confirmed_transaction_list")

            block_serializer = BlockSerializer.new(precommit_block.header.version, self.__tx_versioner)
            block_serialized = block_serializer.serialize(precommit_block)
            block_serialized = json.dumps(block_serialized)
            block_serialized = block_serialized.encode('utf-8')
            results = self._blockchain_store.put(BlockChain.PRECOMMIT_BLOCK_KEY, block_serialized)

            utils.logger.spam(f"result of to write to db ({results})")
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
        utils.logger.spam(f"blockchain:put_nid ({self.__channel_name}), nid ({nid})")
        if nid is None:
            return

        results = self._blockchain_store.put(BlockChain.NID_KEY, nid.encode(encoding=conf.HASH_KEY_ENCODING))
        utils.logger.spam(f"result of to write to db ({results})")

        return results

    def confirm_prev_block(self, current_block: Block):
        """confirm prev unconfirmed block by votes in current block

        :param current_block: Next unconfirmed block what has votes for prev unconfirmed block.
        :return: confirm_Block
        """
        # utils.logger.debug(f"-------------------confirm_prev_block---current_block is "
        #                    f"tx count({len(current_block.body.transactions)}), "
        #                    f"height({current_block.header.height})")

        candidate_blocks = self.__block_manager.candidate_blocks
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
                    if current_block.header.complained and self.__block_manager.epoch.complained_result:
                        utils.logger.debug("reset last_unconfirmed_block by complain block")
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

            # utils.logger.debug(f"-------------------confirm_prev_block---before add block,"
            #                    f"height({unconfirmed_block.header.height})")
            confirm_info = current_block.body.prev_votes if current_block.header.version == "0.3" else None
            self.add_block(unconfirmed_block, confirm_info)
            self.last_unconfirmed_block = current_block
            candidate_blocks.remove_block(current_block.header.prev_hash)

            return unconfirmed_block

    def init_blockchain(self):
        # load last block from key value store. if a block does not exist, genesis block will be made
        try:
            last_block_key = self._blockchain_store.get(BlockChain.LAST_BLOCK_KEY, verify_checksums=True)
        except KeyError:
            last_block_key = None
        logging.debug("LAST BLOCK KEY : %s", last_block_key)

        if last_block_key:
            block_dump = self._blockchain_store.get(last_block_key)
            block_dump = json.loads(block_dump)
            block_height = self.__block_versioner.get_height(block_dump)
            block_version = self.__block_versioner.get_version(block_height)
            confirm_info = self.find_confirm_info_by_hash(self.__block_versioner.get_hash(block_dump))
            block_dump["confirm_prev_block"] = confirm_info is not b''
            self.__last_block = BlockSerializer.new(block_version, self.__tx_versioner).deserialize(block_dump)

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
        utils.logger.spam(f"Try to load a file of initial genesis block from ({genesis_data_path})")
        try:
            with open(genesis_data_path, encoding="utf-8") as json_file:
                tx_info = json.load(json_file)["transaction_data"]
                nid = tx_info["nid"]
                # utils.logger.spam(f"generate_genesis_block::tx_info >>>> {tx_info}")

        except FileNotFoundError as e:
            exit(f"cannot open json file in ({genesis_data_path}): {e}")
        except KeyError as e:
            exit(f"cannot find key name of {e} in genesis data file.")

        self.__add_genesis_block(tx_info, reps)
        self.put_nid(nid)
        self.__nid = nid

        utils.logger.spam(f"add_genesis_block({self.__channel_name}/nid({nid}))")

    def block_dumps(self, block: Block) -> bytes:
        block_version = self.__block_versioner.get_version(block.header.height)
        block_serializer = BlockSerializer.new(block_version, self.__tx_versioner)
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
        block_serializer = BlockSerializer.new(block_version, self.__tx_versioner)
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
        return block_prover.prove(tx_hash, block.header.transactions_hash, proof)

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
        receipts_hash = block_prover.to_hash32(tx_result)
        return block_prover.get_proof(receipts_hash)

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

        block_prover = BlockProver.new(block.header.version, None, BlockProverType.Receipt)  # Do not need receipts
        receipts_hash = block_prover.to_hash32(tx_result)
        return block_prover.prove(receipts_hash, block.header.receipts_hash, proof)

    def get_invoke_func(self, height):
        if height == 0:
            return self.genesis_invoke
        else:
            return self.score_invoke

    def genesis_invoke(self, block: Block, prev_block_ = None) -> ('Block', dict):
        method = "icx_sendTransaction"
        transactions = []
        for tx in block.body.transactions.values():
            tx_serializer = TransactionSerializer.new(tx.version, tx.type(), self.__tx_versioner)
            transaction = {
                "method": method,
                "params": {
                    "txHash": tx.hash.hex()
                },
                "genesisData": tx_serializer.to_full_data(tx)
            }
            transactions.append(transaction)

        request = {
            'block': {
                'blockHeight': block.header.height,
                'blockHash': block.header.hash.hex(),
                'timestamp': block.header.timestamp
            },
            'transactions': transactions
        }
        request = convert_params(request, ParamType.invoke)
        stub = StubCollection().icon_score_stubs[self.__channel_name]
        response = stub.sync_task().invoke(request)
        response_to_json_query(response)

        tx_receipts = response["txResults"]
        block_builder = BlockBuilder.from_new(block, self.__tx_versioner)
        block_builder.reset_cache()
        block_builder.peer_id = block.header.peer_id
        block_builder.commit_state = {
            self.__channel_name: response['stateRootHash']
        }
        block_builder.state_hash = Hash32(bytes.fromhex(response['stateRootHash']))
        block_builder.receipts = tx_receipts
        block_builder.reps = ObjectManager().channel_service.get_rep_ids()
        if block.header.peer_id and block.header.peer_id.hex_hx() == self.__peer_id:
            block_builder.signer = ChannelProperty().peer_auth
        else:
            block_builder.signature = block.header.signature
        new_block = block_builder.build()
        self.__block_manager.set_old_block_hash(new_block.header.height, new_block.header.hash, block.header.hash)

        for tx_receipt in tx_receipts.values():
            tx_receipt["blockHash"] = new_block.header.hash.hex()

        self.__invoke_results[new_block.header.hash] = (tx_receipts, None)
        return new_block, tx_receipts

    def score_invoke(self, _block: Block, prev_block: Block, is_block_editable: bool = False) -> dict or None:
        method = "icx_sendTransaction"
        transactions = []

        for tx in _block.body.transactions.values():
            tx_serializer = TransactionSerializer.new(tx.version, tx.type(), self.__tx_versioner)
            transaction = {
                "method": method,
                "params": tx_serializer.to_full_data(tx)
            }
            transactions.append(transaction)

        request_origin = {
            'block': {
                'blockHeight': _block.header.height,
                'blockHash': _block.header.hash.hex(),
                'prevBlockHash': _block.header.prev_hash.hex() if _block.header.prev_hash else '',
                'timestamp': _block.header.timestamp
            },
            'isBlockEditable': hex(is_block_editable),
            'transactions': transactions,
            'prevBlockGenerator': prev_block.header.peer_id.hex_hx() if prev_block.header.peer_id else '',
            'prevBlockValidators':
                self.find_preps_ids_by_roothash(prev_block.header.reps_hash)
                if prev_block.header.version != "0.1a"
                else [rep['id'] for rep in ObjectManager().channel_service.peer_manager.get_reps()]
        }

        request = convert_params(request_origin, ParamType.invoke)
        stub = StubCollection().icon_score_stubs[self.__channel_name]
        response: dict = cast(dict, stub.sync_task().invoke(request))
        response_to_json_query(response)

        tx_receipts_origin = response.get("txResults")
        if not isinstance(tx_receipts_origin, dict):
            tx_receipts = {tx_receipt['txHash']: tx_receipt for tx_receipt in cast(list, tx_receipts_origin)}
        else:
            tx_receipts = tx_receipts_origin

        next_prep = response.get("prep")
        if next_prep:
            utils.logger.debug(f"in score invoke next_prep({next_prep})")
            next_preps_hash = Hash32.fromhex(next_prep["rootHash"], ignore_prefix=True)
        else:
            next_preps_hash = None

        if prev_block.header.version != "0.1a":
            reps = self.find_preps_addresses_by_roothash(_block.header.reps_hash)
        else:
            reps = ObjectManager().channel_service.get_rep_ids()

        block_builder = BlockBuilder.from_new(_block, self.__tx_versioner)
        block_builder.reset_cache()
        block_builder.peer_id = _block.header.peer_id

        added_transactions = response.get("addedTransactions")
        if added_transactions:
            original_transactions = block_builder.transactions.copy()
            block_builder.transactions.clear()

            for tx_receipt in tx_receipts_origin:
                try:
                    tx_data = added_transactions[tx_receipt['txHash']]
                    tx_version, tx_type = self.__tx_versioner.get_version(tx_data)
                    ts = TransactionSerializer.new(tx_version, tx_type, self.__tx_versioner)
                    tx = ts.from_(tx_data)
                except KeyError:
                    tx = original_transactions[Hash32(bytes.fromhex(tx_receipt['txHash']))]
                block_builder.transactions[tx.hash] = tx

        block_builder.commit_state = {
            self.__channel_name: response['stateRootHash']
        }
        block_builder.state_hash = Hash32(bytes.fromhex(response['stateRootHash']))
        block_builder.receipts = tx_receipts
        block_builder.reps = reps
        block_builder.next_reps_hash = next_preps_hash

        if _block.header.peer_id.hex_hx() == self.__peer_id:
            block_builder.signer = ChannelProperty().peer_auth
        else:
            block_builder.signature = _block.header.signature
        new_block = block_builder.build()
        self.__block_manager.set_old_block_hash(new_block.header.height, new_block.header.hash, _block.header.hash)

        for tx_receipt in tx_receipts.values():
            tx_receipt["blockHash"] = new_block.header.hash.hex()

        self.__invoke_results[new_block.header.hash] = (tx_receipts, next_prep)
        return new_block, tx_receipts
