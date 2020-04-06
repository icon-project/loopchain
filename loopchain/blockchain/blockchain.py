"""Block chain class with authorized blocks only"""

import json
import pickle
import threading
from collections import Counter
from enum import Enum
from functools import lru_cache
from os import linesep
from types import MappingProxyType
from typing import Union, List, cast, Optional, Tuple, Sequence, Mapping

import zlib
from pkg_resources import parse_version

from loopchain import configure as conf
from loopchain import utils
from loopchain.baseservice import ScoreResponse, ObjectManager
from loopchain.baseservice.aging_cache import AgingCache
from loopchain.baseservice.lru_cache import lru_cache as valued_only_lru_cache
from loopchain.blockchain.blocks import Block, BlockBuilder, BlockSerializer, BlockHeader, v0_1a
from loopchain.blockchain.blocks import BlockProver, BlockProverType, BlockVersioner, NextRepsChangeReason
from loopchain.blockchain.exception import *
from loopchain.blockchain.peer_loader import PeerLoader
from loopchain.blockchain.score_base import *
from loopchain.blockchain.transactions import Transaction, TransactionBuilder
from loopchain.blockchain.transactions import TransactionSerializer, TransactionVersioner
from loopchain.blockchain.types import Hash32, ExternalAddress, TransactionStatusInQueue
from loopchain.blockchain.votes import Votes
from loopchain.blockchain.votes.v0_1a import BlockVotes
from loopchain.channel.channel_property import ChannelProperty
from loopchain.configure_default import NodeType
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

    def __init__(self, channel_name=None, store_id=None, block_manager=None):
        if channel_name is None:
            channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL

        # last block in block db
        self.__last_block = None
        self.__made_block_counter = MadeBlockCounter()

        # last unconfirmed block that the leader broadcast.
        self.last_unconfirmed_block = None
        self.__channel_name = channel_name
        self.__peer_id = ChannelProperty().peer_id
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

        self._init_blockchain()

    @property
    def leader_made_block_count(self) -> int:
        if self.__last_block:
            return self.__made_block_counter[self.__last_block.header.peer_id]
        return -1

    @property
    def my_made_block_count(self) -> int:
        return self.__made_block_counter[ChannelProperty().peer_address]

    def made_block_count_reached_max(self, block: Block) -> bool:
        return self.__made_block_counter[block.header.peer_id] == (conf.MAX_MADE_BLOCK_COUNT - 1)

    def _increase_made_block_count(self, block: Block) -> None:
        """This is must called before changing self.__last_block!

        :param block:
        :return:
        """
        if block.header.height == 0:
            return

        if (self.__last_block.header.peer_id != block.header.peer_id or
                self.__last_block.header.prep_changed_reason is NextRepsChangeReason.TermEnd):
            self.__made_block_counter[block.header.peer_id] = 1
        else:
            self.__made_block_counter[block.header.peer_id] += 1

    def _keep_order_in_penalty(self) -> bool:
        keep_order = (self.last_block and
                      self.last_block.header.prep_changed_reason is NextRepsChangeReason.Penalty and
                      self.last_block.header.peer_id == self.last_block.header.next_leader)

        utils.logger.debug(f"_keep_order_in_penalty() : keep_order = {keep_order}")
        return keep_order

    def reset_leader_made_block_count(self, need_check_switched_role: bool = False):
        """Clear all made_block_counter

        :return:
        """
        if need_check_switched_role:
            if self.__last_block.header.prep_changed_reason == NextRepsChangeReason.NoChange:
                utils.logger.debug(f"There is no change in reps.")
                return

            new_reps = self.find_preps_addresses_by_roothash(self.__last_block.header.revealed_next_reps_hash)
            new_node_type = NodeType.CommunityNode if ChannelProperty().peer_address in new_reps else NodeType.CitizenNode
            is_switched_role = new_node_type != ChannelProperty().node_type
        else:
            is_switched_role = False

        utils.logger.debug(f"reset_leader_made_block_count() : made_block_count = {self.__made_block_counter}")
        if not self._keep_order_in_penalty() or is_switched_role:
            self.__made_block_counter.clear()

    def get_first_leader_of_next_reps(self, block: Block) -> str:
        utils.logger.spam(
            f"in get_next_leader new reps leader is "
            f"{self.find_preps_ids_by_roothash(block.header.revealed_next_reps_hash)[0]}")
        return self.find_preps_ids_by_roothash(block.header.revealed_next_reps_hash)[0]

    @staticmethod
    def get_next_rep_in_reps(rep, reps: Sequence[ExternalAddress]):
        try:
            return reps[reps.index(rep) + 1]
        except IndexError:
            return reps[0]
        except ValueError:
            utils.logger.debug(f"rep({rep}) not in reps({[str(rep) for rep in reps]})")
            return None

    @staticmethod
    def get_next_rep_string_in_reps(rep, reps: Sequence[ExternalAddress]) -> Optional[str]:
        try:
            return reps[reps.index(rep) + 1].hex_hx()
        except IndexError:
            return reps[0].hex_hx()
        except ValueError:
            utils.logger.debug(f"rep({rep}) not in reps({[str(rep) for rep in reps]})")
            return None

    def get_expected_generator(self, new_block: Block) -> Optional[ExternalAddress]:
        """get expected generator to vote unconfirmed block

        :return: expected generator's id by made block count.
        """

        peer_id = new_block.header.peer_id
        if self.__made_block_counter[peer_id] > conf.MAX_MADE_BLOCK_COUNT:
            utils.logger.debug(
                f"get_expected_generator made_block_count reached!({self.__made_block_counter})")
            reps: Sequence[ExternalAddress] = \
                self.find_preps_addresses_by_roothash(self.__last_block.header.revealed_next_reps_hash)
            expected_generator = self.get_next_rep_in_reps(peer_id, reps)
        else:
            expected_generator = peer_id

        utils.logger.debug(f"get_expected_generator ({expected_generator})")
        return expected_generator

    @property
    def block_height(self):
        try:
            return self.__last_block.header.height
        except AttributeError:
            return -1

    @property
    def total_tx(self):
        return self.__total_tx

    @property
    def last_block(self) -> Block:
        return self.__last_block

    @property
    def latest_block(self) -> Block:
        return self.last_unconfirmed_block or self.__last_block

    @property
    def block_versioner(self):
        return self.__block_versioner

    @property
    def tx_versioner(self):
        return self.__tx_versioner

    @property
    def blockchain_store(self) -> KeyValueStore:
        return self._blockchain_store

    def close_blockchain_store(self):
        print(f"close blockchain_store = {self._blockchain_store}")
        if self._blockchain_store:
            self._blockchain_store.close()
            self._blockchain_store: KeyValueStore = None

    def check_rollback_possible(self, target_block, start_block=None):
        """Check if the target block can be reached with the prev_hash of last_block.
        CAUTION! This method is called recursively.

        :param target_block:
        :param start_block:
        :return:
        """
        if not start_block:
            start_block = self.__last_block

        if target_block == start_block:
            return True
        else:
            prev_block = self.find_block_by_hash32(start_block.header.prev_hash)
            if not prev_block:
                return False

            return self.check_rollback_possible(target_block, prev_block)

    def __remove_block_up_to_target(self, target_block: Block):
        """CAUTION! This method is called recursively.

        :param target_block:
        :return:
        """
        block_to_be_removed: Block = self.__last_block

        if block_to_be_removed == target_block:
            return target_block
        else:
            with self.__add_block_lock:
                new_last_block: Block = self.find_block_by_hash32(block_to_be_removed.header.prev_hash)
                self.__total_tx -= (
                        len(block_to_be_removed.body.transactions) +
                        len(new_last_block.body.transactions)
                )

                confirm_info = self.__get_confirm_info_from_block(block_to_be_removed)
                next_total_tx = self.__write_block_data(new_last_block,
                                                        confirm_info,
                                                        receipts=None,
                                                        next_prep=None)

                for index, tx in enumerate(block_to_be_removed.body.transactions.values()):
                    tx_hash = tx.hash.hex()
                    self._blockchain_store.delete(tx_hash.encode(encoding=conf.HASH_KEY_ENCODING))

                self.__last_block = new_last_block
                self.__total_tx = next_total_tx

                logging.warning(
                    f"REMOVE BLOCK HEIGHT : {block_to_be_removed.header.height} , "
                    f"HASH : {block_to_be_removed.header.hash.hex()} , "
                    f"CHANNEL : {self.__channel_name}")

                return self.__remove_block_up_to_target(target_block)

    def roll_back(self, target_block):
        self.__remove_block_up_to_target(target_block)

    def rebuild_made_block_count(self):
        """rebuild leader's made block count

        :return:
        """
        self.reset_leader_made_block_count()

        block_hash = self.__last_block.header.hash.hex()
        block_height = self.__last_block.header.height

        while block_hash != "":
            if block_height <= 0:
                return

            block_dump = self._blockchain_store.get(block_hash.encode(encoding='UTF-8'))
            block_version = self.__block_versioner.get_version(block_height)
            block_serializer = BlockSerializer.new(block_version, self.__tx_versioner)
            block = block_serializer.deserialize(json.loads(block_dump))

            if self.__last_block.header.peer_id != block.header.peer_id:
                break

            self._increase_made_block_count(block)

            # next loop
            block_height = block.header.height - 1
            block_hash = block.header.prev_hash.hex()

    def rebuild_transaction_count(self):
        if self.__last_block is not None:
            # rebuild blocks to Genesis block.
            logging.info("re-build transaction count from DB....")

            try:
                self.__total_tx = self._rebuild_transaction_count_from_cached()
            except Exception as e:
                if isinstance(e, KeyError):
                    logging.warning(f"Cannot find 'TRANSACTION_COUNT' Key from DB. Rebuild tx count")
                else:
                    logging.warning(f"Exception raised on getting 'TRANSACTION_COUNT' from DB. Rebuild tx count,"
                                    f"Exception : {type(e)}, {e}")
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
            logging.debug(f"__find_block_by_key::KeyError block_hash({key}) error({e})")

        return None

    def get_prev_block(self, block: Block) -> Block:
        """get prev block by given block

        :param block: Block
        :return: prev_block (from blockchain or DB) by given block
        """
        prev_hash = block.header.prev_hash
        candidate_blocks = self.__block_manager.candidate_blocks

        try:
            prev_block = candidate_blocks.blocks[prev_hash].block
            if not prev_block:
                raise BlockNotExist
        except (BlockNotExist, KeyError):
            utils.logger.spam(f"prev_block is not in candidate_blocks by prev_hash({prev_hash})")
            prev_block = self.find_block_by_hash32(prev_hash) or self.last_block

        return prev_block

    def find_block_by_hash(self, block_hash: Union[str, Hash32]):
        """find block in DB by block hash.

        :param block_hash: plain string,
        key 로 사용되기전에 함수내에서 encoding 되므로 미리 encoding 된 key를 parameter 로 사용해선 안된다.
        :return: None or Block
        """
        if isinstance(block_hash, Hash32):
            block_hash = block_hash.hex()
        return self.__find_block_by_key(block_hash.encode(encoding='UTF-8'))

    def find_block_by_hash_str(self, block_hash: str):
        """find block in DB by block hash.

        :param block_hash: plain string,
        :return: None or Block
        """
        return self.__find_block_by_key(block_hash.encode(encoding='UTF-8'))

    def find_block_by_hash32(self, block_hash: Hash32):
        """find block in DB by block hash.

        :param block_hash: Hash32
        :return: None or Block
        """
        return self.__find_block_by_key(block_hash.hex().encode(encoding='UTF-8'))

    def find_block_by_height(self, block_height):
        """find block in DB by its height

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

    def find_confirm_info_by_hash(self, block_hash: Union[str, Hash32]) -> bytes:
        if isinstance(block_hash, Hash32):
            block_hash = block_hash.hex()
        hash_encoded = block_hash.encode('UTF-8')
        try:
            return self._blockchain_store.get(BlockChain.CONFIRM_INFO_KEY + hash_encoded)
        except KeyError:
            utils.logger.debug(f"There is no confirm info by block hash: {block_hash}")
            block = self.find_block_by_hash_str(block_hash)
            return self.find_prev_confirm_info_by_height(block.header.height + 1) if block else bytes()

    def find_prev_confirm_info_by_hash(self, block_hash: Union[str, Hash32]) -> bytes:
        block = self.find_block_by_hash(block_hash)
        if block and not isinstance(block.body, v0_1a.BlockBody):
            votes_serialized = BlockVotes.serialize_votes(block.body.prev_votes)
            return json.dumps(votes_serialized).encode(encoding='UTF-8')
        return bytes()

    def find_prev_confirm_info_by_height(self, height: int) -> bytes:
        block = self.find_block_by_height(height)
        return self.__get_confirm_info_from_block(block)

    def __get_confirm_info_from_block(self, block) -> bytes:
        if block and not isinstance(block.body, v0_1a.BlockBody):
            votes_serialized = BlockVotes.serialize_votes(block.body.prev_votes)
            return json.dumps(votes_serialized).encode(encoding='UTF-8')
        return bytes()

    @lru_cache(maxsize=4)
    def find_preps_ids_by_roothash(self, roothash: Hash32) -> Tuple[str, ...]:
        preps = self.find_preps_by_roothash(roothash)
        return tuple([prep["id"] for prep in preps])

    @lru_cache(maxsize=4)
    def find_preps_addresses_by_roothash(self, roothash: Hash32) -> Tuple[ExternalAddress, ...]:
        preps_ids = self.find_preps_ids_by_roothash(roothash)
        return tuple([ExternalAddress.fromhex(prep_id) for prep_id in preps_ids])

    @lru_cache(maxsize=4)
    def find_preps_targets_by_roothash(self, roothash: Hash32) -> Mapping[str, str]:
        preps = self.find_preps_by_roothash(roothash)
        return MappingProxyType({prep["id"]: prep["p2pEndpoint"] for prep in preps})

    def __cache_clear_roothash(self):
        self.find_preps_ids_by_roothash.cache_clear()
        self.find_preps_addresses_by_roothash.cache_clear()
        self.find_preps_targets_by_roothash.cache_clear()

    @staticmethod
    def get_reps_hash_by_header(header: BlockHeader) -> Hash32:
        try:
            roothash = header.reps_hash
            if not roothash:
                raise AttributeError
        except AttributeError:
            roothash = ChannelProperty().crep_root_hash
        return roothash

    @staticmethod
    def get_next_reps_hash_by_header(header: BlockHeader) -> Hash32:
        try:
            roothash = header.revealed_next_reps_hash
            if not roothash:
                raise AttributeError
        except AttributeError:
            # TODO: Re-locate roothash under BlockHeader or somewhere, without use ObjectManager
            roothash = ChannelProperty().crep_root_hash
        return roothash

    def find_preps_ids_by_header(self, header: BlockHeader) -> Sequence[str]:
        return self.find_preps_ids_by_roothash(self.get_reps_hash_by_header(header))

    def find_preps_addresses_by_header(self, header: BlockHeader) -> Sequence[ExternalAddress]:
        return self.find_preps_addresses_by_roothash(self.get_reps_hash_by_header(header))

    def find_preps_by_roothash(self, roothash: Hash32) -> list:
        try:
            preps_dumped = bytes(self._blockchain_store.get(BlockChain.PREPS_KEY + roothash))
        except (KeyError, TypeError):
            return []
        else:
            return json.loads(preps_dumped)

    @valued_only_lru_cache(maxsize=4, valued_returns_only=True)
    def is_roothash_exist_in_db(self, roothash: Hash32) -> Optional[bool]:
        try:
            self._blockchain_store.get(BlockChain.PREPS_KEY + roothash)
        except (KeyError, TypeError):
            return None
        else:
            return True

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

            peer_id = ChannelProperty().peer_id
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
            channel_service = ObjectManager().channel_service

            receipts, next_prep = self.__invoke_results.get(block.header.hash, (None, None))
            if receipts is None and need_to_score_invoke:
                self.get_invoke_func(block.header.height)(block, self.__last_block)
                receipts, next_prep = self.__invoke_results.get(block.header.hash, (None, None))

            if not need_to_write_tx_info:
                receipts = None

            if next_prep and self.find_preps_addresses_by_roothash(
                    Hash32.fromhex(next_prep['rootHash'], ignore_prefix=True)):
                next_prep = None

            next_total_tx = self.__write_block_data(block, confirm_info, receipts, next_prep)

            try:
                if need_to_score_invoke:
                    channel_service.score_write_precommit_state(block)
            except Exception as e:
                utils.exit_and_msg(f"score_write_precommit_state FAIL {e}")

            self.__invoke_results.pop(block.header.hash, None)
            self._increase_made_block_count(block)  # must do this before self.__last_block = block
            self.__last_block = block
            self.__total_tx = next_total_tx
            self.__block_manager.new_epoch()

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
                    'block_height': self.__last_block.header.height
                }})

            if not (conf.SAFE_BLOCK_BROADCAST and channel_service.state_machine.state == 'BlockGenerate'):
                channel_service.inner_service.notify_new_block()
                channel_service.reset_leader(new_leader_id=self.__block_manager.epoch.leader_id)

            if block.header.prep_changed and channel_service.state_machine.state != 'BlockSync':
                # reset_network_by_block_height is called in critical section by self.__add_block_lock.
                # Other Blocks must not be added until reset_network_by_block_height function finishes.
                channel_service.switch_role()

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
            utils.logger.spam(
                f"store next_prep in __write_block_data\nprep_hash({next_prep['rootHash']})"
                f"\npreps({next_prep['preps']})")
            self.write_preps(Hash32.fromhex(next_prep['rootHash'], ignore_prefix=True), next_prep['preps'], batch)

        if confirm_info:
            if isinstance(confirm_info, list):
                votes_class = Votes.get_block_votes_class(block.header.version)
                confirm_info = json.dumps(votes_class.serialize_votes(confirm_info))
            if isinstance(confirm_info, str):
                confirm_info = confirm_info.encode('utf-8')
            batch.put(
                BlockChain.CONFIRM_INFO_KEY + block_hash_encoded,
                confirm_info
            )
        else:
            utils.logger.debug(f"This block({block.header.hash}) is trying to add without confirm_info.")

        if self.__last_block and self.__last_block.header.prev_hash:
            # Delete confirm info to avoid data duplication.
            block_hash_encoded = self.__last_block.header.prev_hash.hex().encode("utf-8")
            block_confirm_info_key = BlockChain.CONFIRM_INFO_KEY + block_hash_encoded
            batch.delete(block_confirm_info_key)

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
                try:
                    ObjectManager().channel_service.score_write_precommit_state(invoke_block)
                except Exception as e:
                    utils.exit_and_msg(f"Fail to write precommit in the score.: {e}")

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
        utils.logger.spam(f"put_nid ({self.__channel_name}), nid ({nid})")
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
        candidate_blocks = self.__block_manager.candidate_blocks
        with self.__confirmed_block_lock:
            logging.debug(f"confirm_prev_block with "
                          f"current_block({current_block.header.height}, {current_block.header.hash})")

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
                    if ((current_block.header.complained and self.__block_manager.epoch.complained_result)
                            or self.last_block.header.prep_changed):
                        utils.logger.debug("reset last_unconfirmed_block by complain block or first block of new term.")
                        self.last_unconfirmed_block = current_block
                    return None
                else:
                    except_msg = ("there is no unconfirmed block in this peer "
                                  f"block_hash({current_block.header.prev_hash.hex()})")
                    logging.warning(except_msg)
                    raise BlockchainError(except_msg)

            if unconfirmed_block.header.hash != current_block.header.prev_hash:
                raise BlockchainError(
                    f"It couldn't be confirmed by the new block. "
                    f"Hash of last_unconfirmed_block({unconfirmed_block.header.hash})\n"
                    f"prev_hash of the new unconfirmed_block({current_block.header.prev_hash})"
                )

            if parse_version(current_block.header.version) >= parse_version("0.3"):
                confirm_info = current_block.body.prev_votes
                round_ = next(vote for vote in confirm_info if vote).round

                if round_ != self.__block_manager.epoch.round:
                    raise RoundMismatch(
                        f"It doesn't match the round of the current epoch.\n"
                        f"current({self.__block_manager.epoch.round}) / "
                        f"unconfirmed_block({round_})"
                    )
            else:
                confirm_info = None

            self.add_block(unconfirmed_block, confirm_info)
            self.last_unconfirmed_block = current_block
            candidate_blocks.remove_block(current_block.header.prev_hash)

            return unconfirmed_block

    def _init_blockchain(self):
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

    def init_crep_reps(self) -> None:
        if not self.is_roothash_exist_in_db(ChannelProperty().crep_root_hash):
            reps_hash, reps = PeerLoader.load()
            utils.logger.info(f"Initial Loaded Reps: {reps}")
            if not self.is_roothash_exist_in_db(reps_hash):
                self.write_preps(reps_hash, reps)

    def generate_genesis_block(self, reps: List[ExternalAddress]):
        tx_info = None
        nid = NID.unknown.value
        genesis_data_path = conf.CHANNEL_OPTION[self.__channel_name]["genesis_data_path"]
        utils.logger.spam(f"Try to load a file of initial genesis block from ({genesis_data_path})")
        try:
            with open(genesis_data_path, encoding="utf-8") as json_file:
                tx_info = json.load(json_file)["transaction_data"]
                nid = tx_info["nid"]

        except FileNotFoundError as e:
            exit(f"cannot open json file in ({genesis_data_path}): {e}")
        except KeyError as e:
            exit(f"cannot find key name of {e} in genesis data file.")

        self.__add_genesis_block(tx_info, reps)
        self.put_nid(nid)
        ChannelProperty().nid = nid

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

    def genesis_invoke(self, block: Block, prev_block_=None) -> Tuple[Block, dict]:
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
        stub = StubCollection().icon_score_stubs[ChannelProperty().name]
        response = stub.sync_task().invoke(request)
        response_to_json_query(response)

        tx_receipts = response["txResults"]
        block_builder = BlockBuilder.from_new(block, self.__tx_versioner)
        block_builder.reset_cache()
        block_builder.peer_id = block.header.peer_id
        block_builder.commit_state = {
            ChannelProperty().name: response['stateRootHash']
        }
        block_builder.state_hash = Hash32(bytes.fromhex(response['stateRootHash']))
        block_builder.receipts = tx_receipts
        block_builder.reps = self.find_preps_addresses_by_roothash(ChannelProperty().crep_root_hash)
        if block.header.peer_id and block.header.peer_id.hex_hx() == ChannelProperty().peer_id:
            block_builder.signer = ChannelProperty().peer_auth
        else:
            block_builder.signature = block.header.signature
        new_block = block_builder.build()
        self.__block_manager.set_old_block_hash(new_block.header.height, new_block.header.hash, block.header.hash)

        for tx_receipt in tx_receipts.values():
            tx_receipt["blockHash"] = new_block.header.hash.hex()

        self.__invoke_results[new_block.header.hash] = (tx_receipts, None)
        return new_block, tx_receipts

    def _process_next_prep_legacy(self, _block: Block, block_builder: BlockBuilder, next_prep: dict):
        next_leader = _block.header.next_leader

        if next_prep:
            # P-Rep list has been changed
            utils.logger.debug(f"_process_next_prep_legacy() current_height({_block.header.height})"
                               f" next_prep({next_prep})")

            change_reason = NextRepsChangeReason.convert_to_change_reason(next_prep["state"])
            if change_reason == NextRepsChangeReason.TermEnd:
                next_leader = ExternalAddress.empty()

            next_preps_hash = Hash32.fromhex(next_prep["rootHash"], ignore_prefix=True)
        else:
            # P-Rep list has no changes
            next_leader = _block.header.next_leader
            next_preps_hash = Hash32.empty()

        block_builder.next_leader = next_leader
        block_builder.reps = self.find_preps_addresses_by_header(_block.header)
        block_builder.next_reps_hash = next_preps_hash

    def _process_next_prep(self, _block: Block, block_builder: BlockBuilder, next_prep: dict):
        reps = self.find_preps_addresses_by_header(_block.header)

        if next_prep:
            # P-Rep list has been changed
            utils.logger.debug(f"_process_next_prep() current_height({_block.header.height}),"
                               f" next_prep({next_prep})")

            change_reason = NextRepsChangeReason.convert_to_change_reason(next_prep["state"])

            next_leader = None  # to rebuild next_leader
            block_builder.next_reps_change_reason = change_reason
            block_builder.is_max_made_block_count = self.made_block_count_reached_max(_block)
            utils.logger.debug(f"_process_next_prep() change_reason = {block_builder.next_reps_change_reason},"
                               f" is_max_mbc = {block_builder.is_max_made_block_count}")

            next_preps = [ExternalAddress.fromhex(prep["id"]) for prep in next_prep["preps"]]
            next_preps_hash = None  # to rebuild next_reps_hash
        else:
            # P-Rep list has no changes
            next_leader = _block.header.next_leader
            next_preps = reps
            next_preps_hash = Hash32.empty()

        block_builder.next_leader = next_leader
        block_builder.reps = reps
        block_builder.next_reps = next_preps
        block_builder.next_reps_hash = next_preps_hash

    def _process_added_transactions(self,
                                    block_builder: BlockBuilder,
                                    added_transactions: dict,
                                    tx_receipts: dict,
                                    is_block_editable: bool):
        if is_block_editable:
            original_tx_length: int = len(block_builder.transactions)
            invoked_tx_length: int = len(tx_receipts) - len(added_transactions)
            if original_tx_length > invoked_tx_length:
                # restore tx status to normal and remove tx that dropped in block_builder
                utils.logger.debug(f"_process_added_transactions() : origin tx length = {original_tx_length}, "
                                   f"after invoke tx length = {invoked_tx_length}, "
                                   f"added_transactions length = {len(added_transactions)}")
                dropped_transactions: List[Transaction] = []
                for txhash, tx in reversed(block_builder.transactions.items()):  # type: Hash32, Transaction
                    if txhash.hex() not in tx_receipts:
                        dropped_transactions.append(tx)
                        original_tx_length -= 1
                        if original_tx_length == invoked_tx_length:
                            break

                for tx in dropped_transactions:  # type: Transaction
                    self.__block_manager.restore_tx_status(tx)
                    block_builder.transactions.pop(tx.hash)
                utils.logger.debug(f"_process_added_transactions() dropped tx length = {len(dropped_transactions)}")

        if added_transactions:
            # add added_transactions to block_builder.transactions
            for tx_data in added_transactions.values():  # type: dict
                tx_version, tx_type = self.__tx_versioner.get_version(tx_data)
                ts = TransactionSerializer.new(tx_version, tx_type, self.__tx_versioner)
                tx = ts.from_(tx_data)
                block_builder.transactions[tx.hash] = tx
                block_builder.transactions.move_to_end(tx.hash, last=False)  # move to first

    def score_invoke(self,
                     _block: Block,
                     prev_block: Block,
                     is_block_editable: bool = False,
                     is_unrecorded_block: bool = False) -> Tuple[Block, dict]:
        method = "icx_sendTransaction"
        transactions = []

        for tx in _block.body.transactions.values():
            tx_serializer = TransactionSerializer.new(tx.version, tx.type(), self.__tx_versioner)
            transaction = {
                "method": method,
                "params": tx_serializer.to_full_data(tx)
            }
            transactions.append(transaction)

        prev_vote_results = {}
        prev_block_votes = []

        if prev_block.header.height < 1:
            prev_block_validators = []
        elif prev_block.header.version != "0.1a":
            prev_block_validators = [vote.rep.hex_hx() for vote in _block.body.prev_votes
                                     if vote and vote.rep != prev_block.header.peer_id]
            prev_vote_results = {vote.rep: vote.result() for vote in _block.body.prev_votes
                                 if vote and vote.rep != prev_block.header.peer_id}
        else:
            prev_block_validators = list(self.find_preps_ids_by_header(prev_block.header))
            try:
                prev_block_validators.pop(prev_block_validators.index(prev_block.header.peer_id.hex_hx()))
            except ValueError:
                utils.logger.spam(
                    f"{prev_block.header.peer_id.hex_hx()} is not in validators({prev_block_validators})")

        if prev_vote_results:
            prev_block_votes = [
                [
                    vote_address.hex_hx(),
                    hex((2 - prev_vote_results[vote_address]) if vote_address in prev_vote_results else False)
                ]
                for vote_address in self.find_preps_addresses_by_header(prev_block.header)
                if vote_address != prev_block.header.peer_id
            ]

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
            'prevBlockValidators': prev_block_validators,
            'prevBlockVotes': prev_block_votes
        }

        request = convert_params(request_origin, ParamType.invoke)
        stub = StubCollection().icon_score_stubs[ChannelProperty().name]
        response: dict = cast(dict, stub.sync_task().invoke(request))
        response_to_json_query(response)

        tx_receipts_origin = response.get("txResults")
        if not isinstance(tx_receipts_origin, dict):
            tx_receipts: dict = {tx_receipt['txHash']: tx_receipt for tx_receipt in cast(list, tx_receipts_origin)}
        else:
            tx_receipts: dict = tx_receipts_origin

        block_builder = BlockBuilder.from_new(_block, self.__tx_versioner)
        block_builder.reset_cache()
        block_builder.peer_id = _block.header.peer_id

        next_prep = response.get("prep")

        if is_unrecorded_block:
            block_builder.next_leader = ExternalAddress.empty()
            block_builder.reps = []
            block_builder.next_reps_hash = Hash32.empty()
        else:
            if parse_version(block_builder.version) >= parse_version('0.4'):
                self._process_next_prep(_block, block_builder, next_prep)
            else:
                # TODO : need check that legacy useless after upgrade to block v0.4
                self._process_next_prep_legacy(_block, block_builder, next_prep)

        added_transactions = response.get("addedTransactions")
        self._process_added_transactions(block_builder, added_transactions, tx_receipts, is_block_editable)

        block_builder.commit_state = {
            ChannelProperty().name: response['stateRootHash']
        }
        block_builder.state_hash = Hash32(bytes.fromhex(response['stateRootHash']))
        block_builder.receipts = tx_receipts

        if _block.header.peer_id.hex_hx() == ChannelProperty().peer_id:
            block_builder.signer = ChannelProperty().peer_auth
        else:
            block_builder.signature = _block.header.signature
        new_block = block_builder.build()

        # next_reps_hash can be referenced after build block
        if next_prep:
            self.__write_preps(preps=next_prep["preps"], next_reps_hash=new_block.header.next_reps_hash)
        self.__block_manager.set_old_block_hash(new_block.header.height, new_block.header.hash, _block.header.hash)

        for tx_receipt in tx_receipts.values():
            tx_receipt["blockHash"] = new_block.header.hash.hex()

        self.__invoke_results[new_block.header.hash] = (tx_receipts, next_prep)
        return new_block, tx_receipts

    def __write_preps(self, preps: list, next_reps_hash):
        """Write prep data to DB."""
        self.write_preps(roothash=next_reps_hash, preps=preps)
        self.__cache_clear_roothash()
        ObjectManager().channel_service.broadcast_scheduler.reset_audience_reps_hash()
