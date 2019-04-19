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
"""A management class for blockchain."""

import json
import logging
import shutil
import threading
import traceback
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor, Future
from typing import TYPE_CHECKING

import loopchain.utils as util
from loopchain import configure as conf
from loopchain.baseservice import TimerService, BlockGenerationScheduler, ObjectManager, Timer
from loopchain.baseservice.aging_cache import AgingCache
from loopchain.blockchain import TransactionStatusInQueue, BlockChain, CandidateBlocks, Block, Epoch, Transaction, \
    TransactionInvalidDuplicatedHash, TransactionInvalidOutOfTimeBound, BlockchainError, NID, BlockSerializer, \
    exception, BlockVerifier, InvalidUnconfirmedBlock, DuplicationUnconfirmedBlock
from loopchain.channel.channel_property import ChannelProperty
from loopchain.peer import status_code
from loopchain.peer.consensus_siever import ConsensusSiever
from loopchain.protos import loopchain_pb2, loopchain_pb2_grpc, message_code
from loopchain.tools.grpc_helper import GRPCHelper
from loopchain.utils.message_queue import StubCollection

if TYPE_CHECKING:
    from loopchain.channel.channel_service import ChannelService


class BlockManager:
    """Manage the blockchain of a channel. It has objects for consensus and db object.
    """

    MAINNET = "cf43b3fd45981431a0e64f79d07bfcf703e064b73b802c5f32834eec72142190"
    TESTNET = "885b8021826f7e741be7f53bb95b48221e9ab263f377e997b2e47a7b8f4a2a8b"

    def __init__(self, name: str, channel_manager, peer_id, channel_name, level_db_identity):
        self.__channel_service: ChannelService = channel_manager
        self.__channel_name = channel_name
        self.__pre_validate_strategy = self.__pre_validate
        self.__peer_id = peer_id
        self.__level_db = None
        self.__level_db_path = ""
        self.__level_db, self.__level_db_path = util.init_level_db(
            level_db_identity=f"{level_db_identity}_{channel_name}",
            allow_rename_path=False
        )
        self.__txQueue = AgingCache(max_age_seconds=conf.MAX_TX_QUEUE_AGING_SECONDS,
                                    default_item_status=TransactionStatusInQueue.normal)
        self.__blockchain = BlockChain(self.__level_db, channel_name)
        self.__peer_type = None
        self.__consensus = None
        self.__consensus_algorithm = None
        self.candidate_blocks = CandidateBlocks()
        self.__block_height_sync_lock = threading.Lock()
        self.__block_height_thread_pool = ThreadPoolExecutor(1, 'BlockHeightSyncThread')
        self.__block_height_future: Future = None
        self.__block_generation_scheduler = BlockGenerationScheduler(self.__channel_name)
        self.__precommit_block: Block = None
        self.set_peer_type(loopchain_pb2.PEER)
        self.name = name
        self.__service_status = status_code.Service.online

        self.epoch: Epoch = None

    @property
    def channel_name(self):
        return self.__channel_name

    @property
    def service_status(self):
        # Return string for compatibility.
        if self.__service_status >= 0:
            return "Service is online: " + \
                   str(1 if self.__channel_service.state_machine.state == "BlockGenerate" else 0)
        else:
            return "Service is offline: " + status_code.get_status_reason(self.__service_status)

    def init_epoch(self):
        """Call this after peer list update

        :return:
        """
        self.epoch = Epoch(self)

    def update_service_status(self, status):
        self.__service_status = status
        StubCollection().peer_stub.sync_task().update_status(
            self.__channel_name,
            {"status": self.service_status})

    @property
    def peer_type(self):
        return self.__peer_type

    @property
    def made_block_count(self):
        if self.__consensus_algorithm:
            return self.__consensus_algorithm.made_block_count
        return 0

    @property
    def consensus(self):
        return self.__consensus

    @consensus.setter
    def consensus(self, consensus):
        self.__consensus = consensus

    @property
    def consensus_algorithm(self):
        return self.__consensus_algorithm

    @property
    def precommit_block(self):
        return self.__precommit_block

    @precommit_block.setter
    def precommit_block(self, block):
        self.__precommit_block = block

    @property
    def block_generation_scheduler(self):
        return self.__block_generation_scheduler

    def get_level_db(self):
        return self.__level_db

    def clear_all_blocks(self):
        logging.debug(f"clear level db({self.__level_db_path})")
        shutil.rmtree(self.__level_db_path)

    def set_peer_type(self, peer_type):
        self.__peer_type = peer_type

    async def __create_block_generation_schedule(self):
        # util.logger.spam(f"__create_block_generation_schedule:: CREATE BLOCK GENERATION SCHEDULE")
        if conf.CONSENSUS_ALGORITHM == conf.ConsensusAlgorithm.lft:
            Schedule = namedtuple("Schedule", "callback kwargs")
            schedule = Schedule(self.__consensus_algorithm.consensus, {})
            self.__block_generation_scheduler.add_schedule(schedule)
        else:
            await self.__consensus_algorithm.consensus()

    def set_invoke_results(self, block_hash, invoke_results):
        self.__blockchain.set_invoke_results(block_hash, invoke_results)

    def get_total_tx(self):
        """
        블럭체인의 Transaction total 리턴합니다.

        :return: 블럭체인안의 transaction total count
        """
        return self.__blockchain.total_tx

    def get_blockchain(self):
        return self.__blockchain

    def pre_validate(self, tx: Transaction):
        return self.__pre_validate_strategy(tx)

    def __pre_validate(self, tx: Transaction):
        if tx.hash.hex() in self.__txQueue:
            raise TransactionInvalidDuplicatedHash(tx.hash.hex())

        if not util.is_in_time_boundary(tx.timestamp, conf.ALLOW_TIMESTAMP_BOUNDARY_SECOND):
            raise TransactionInvalidOutOfTimeBound(tx.hash.hex(), tx.timestamp, util.get_now_time_stamp())

    def __pre_validate_pass(self, tx: Transaction):
        pass

    def broadcast_send_unconfirmed_block(self, block_: Block):
        """생성된 unconfirmed block 을 피어들에게 broadcast 하여 검증을 요청한다.
        """
        if self.__channel_service.state_machine.state == "BlockGenerate":
            logging.debug(f"BroadCast AnnounceUnconfirmedBlock "
                          f"height({block_.header.height}) block({block_.header.hash}) peers: "
                          f"{ObjectManager().channel_service.peer_manager.get_peer_count()}")

            # util.logger.spam(f'block_manager:zip_test num of tx is {block_.confirmed_tx_len}')
            block_dumped = self.__blockchain.block_dumps(block_)

            ObjectManager().channel_service.broadcast_scheduler.schedule_broadcast(
                "AnnounceUnconfirmedBlock",
                loopchain_pb2.BlockSend(
                    block=block_dumped,
                    channel=self.__channel_name))

    def add_tx_obj(self, tx):
        """전송 받은 tx 를 Block 생성을 위해서 큐에 입력한다. load 하지 않은 채 입력한다.

        :param tx: transaction object
        """
        self.__txQueue[tx.hash.hex()] = tx

    def get_tx(self, tx_hash) -> Transaction:
        """Get transaction from block_db by tx_hash

        :param tx_hash: tx hash
        :return: tx object or None
        """
        return self.__blockchain.find_tx_by_key(tx_hash)

    def get_tx_info(self, tx_hash) -> dict:
        """Get transaction info from block_db by tx_hash

        :param tx_hash: tx hash
        :return: {'block_hash': "", 'block_height': "", "transaction": "", "result": {"code": ""}}
        """
        return self.__blockchain.find_tx_info(tx_hash)

    def get_invoke_result(self, tx_hash):
        """ get invoke result by tx

        :param tx_hash:
        :return:
        """
        return self.__blockchain.find_invoke_result_by_tx_hash(tx_hash)

    def get_tx_queue(self):
        if conf.CONSENSUS_ALGORITHM == conf.ConsensusAlgorithm.lft:
            return self.__consensus.get_tx_queue()

        return self.__txQueue

    def get_count_of_unconfirmed_tx(self):
        """BlockManager 의 상태를 확인하기 위하여 현재 입력된 unconfirmed_tx 의 카운트를 구한다.

        :return: 현재 입력된 unconfirmed tx 의 갯수
        """
        return len(self.__txQueue)

    def confirm_prev_block(self, current_block: Block):
        confirmed_block = self.__blockchain.confirm_prev_block(current_block)
        if confirmed_block is None:
            return

        # stop leader complain timer
        self.__channel_service.stop_leader_complain_timer()

        # start new epoch
        if not current_block.header.complained:
            self.epoch = Epoch.new_epoch()

    def __validate_duplication_unconfirmed_block(self, unconfirmed_block: Block):
        last_unconfirmed_block: Block = self.__blockchain.last_unconfirmed_block
        try:
            candidate_block = self.candidate_blocks.blocks[unconfirmed_block.header.hash].block
        except KeyError:
            # When an unconfirmed block confirmed previous block, the block become last unconfirmed block,
            # But if the block is failed to verify, the block doesn't be added into candidate block.
            candidate_block: Block = last_unconfirmed_block

        if candidate_block is None or unconfirmed_block.header.hash != candidate_block.header.hash:
            return

        if self.__channel_service.state_machine.state == 'LeaderComplain' \
                and self.epoch.leader_id == unconfirmed_block.header.peer_id.hex_hx():
            raise InvalidUnconfirmedBlock(f"Unconfirmed block is made by complained leader. {unconfirmed_block})")

        raise DuplicationUnconfirmedBlock("Unconfirmed block has already been added.")

    def add_unconfirmed_block(self, unconfirmed_block):
        """

        :param unconfirmed_block:
        """
        logging.info(f"unconfirmed_block {unconfirmed_block.header.height}, {unconfirmed_block.body.confirm_prev_block}")

        self.__validate_duplication_unconfirmed_block(unconfirmed_block)

        # TODO set below variable with right result.
        check_unconfirmed_block_has_valid_block_info_for_prev_block = True
        if not check_unconfirmed_block_has_valid_block_info_for_prev_block:
            raise InvalidUnconfirmedBlock("Unconfirmed block has no valid block info for previous block")

        last_unconfirmed_block: Block = self.__blockchain.last_unconfirmed_block

        try:
            if unconfirmed_block.body.confirm_prev_block:
                self.confirm_prev_block(unconfirmed_block)
            elif last_unconfirmed_block is None:
                if self.__blockchain.last_block.header.hash != unconfirmed_block.header.prev_hash:
                    raise BlockchainError(f"last block is not previous block. block={unconfirmed_block}")

                self.__blockchain.last_unconfirmed_block = unconfirmed_block
                self.__channel_service.stop_leader_complain_timer()
        except BlockchainError as e:
            logging.warning(f"BlockchainError while confirm_block({e}), retry block_height_sync")
            self.__channel_service.state_machine.block_sync()
            raise InvalidUnconfirmedBlock(e)

    def add_confirmed_block(self, confirmed_block: Block):
        my_height = self.__blockchain.last_block.header.height
        if confirmed_block.header.height == my_height + 1:
            result = self.__blockchain.add_block(confirmed_block)
            if result:
                return

        self.block_height_sync()

    def rebuild_block(self):
        self.__blockchain.rebuild_transaction_count()

        nid = self.get_blockchain().find_nid()
        if nid is None:
            genesis_block = self.get_blockchain().find_block_by_height(0)
            self.__rebuild_nid(genesis_block)
        else:
            ChannelProperty().nid = nid

    def __rebuild_nid(self, block: Block):
        nid = NID.unknown.value
        if block.header.hash.hex() == BlockManager.MAINNET:
            nid = NID.mainnet.value
        elif block.header.hash.hex() == BlockManager.TESTNET:
            nid = NID.testnet.value
        elif len(block.body.transactions) > 0:
            tx = next(iter(block.body.transactions.values()))
            nid = tx.nid
            if nid is None:
                nid = NID.unknown.value

        if isinstance(nid, int):
            nid = hex(nid)

        self.get_blockchain().put_nid(nid)
        ChannelProperty().nid = nid

    def block_height_sync(self):
        with self.__block_height_sync_lock:
            need_to_sync = (self.__block_height_future is None or self.__block_height_future.done())

            if need_to_sync:
                self.__channel_service.stop_leader_complain_timer()
                self.__block_height_future = self.__block_height_thread_pool.submit(self.__block_height_sync)
            else:
                logging.warning('Tried block_height_sync. But failed. The thread is already running')

            return need_to_sync, self.__block_height_future

    def __block_request(self, peer_stub, block_height):
        """request block by gRPC or REST

        :param peer_stub:
        :param block_height:
        :return block, max_block_height, confirm_info, response_code
        """
        if ObjectManager().channel_service.is_support_node_function(conf.NodeFunction.Vote):
            response = peer_stub.BlockSync(loopchain_pb2.BlockSyncRequest(
                block_height=block_height,
                channel=self.__channel_name
            ), conf.GRPC_TIMEOUT)
            try:
                block = self.__blockchain.block_loads(response.block)
            except Exception as e:
                traceback.print_exc()
                raise exception.BlockError(f"Received block is invalid: original exception={e}")
            return block, response.max_block_height, response.unconfirmed_block_height,\
                response.confirm_info, response.response_code
        else:
            # request REST(json-rpc) way to RS peer
            return self.__block_request_by_citizen(block_height, ObjectManager().channel_service.radio_station_stub)

    def __block_request_by_citizen(self, block_height, rs_rest_stub):
        get_block_result = rs_rest_stub.call(
            "GetBlockByHeight", {
                'channel': self.__channel_name,
                'height': str(block_height)
            }
        )
        max_height_result = rs_rest_stub.call("Status")

        if max_height_result.status_code != 200:
            raise ConnectionError

        block_version = self.get_blockchain().block_versioner.get_version(block_height)
        block_serializer = BlockSerializer.new(block_version, self.get_blockchain().tx_versioner)
        block = block_serializer.deserialize(get_block_result['block'])
        confirm_info = get_block_result['confirm_info'] if 'confirm_info' in get_block_result else None

        return block, json.loads(max_height_result.text)['block_height'], -1, confirm_info, message_code.Response.success

    def __precommit_block_request(self, peer_stub, last_block_height):
        """request precommit block by gRPC

        :param peer_stub:
        :param block_height:
        :return block, max_block_height, response_code
        """
        response = peer_stub.GetPrecommitBlock(loopchain_pb2.PrecommitBlockRequest(
            last_block_height=last_block_height,
            channel=self.__channel_name
        ), conf.GRPC_TIMEOUT)

        if response.block == b"":
            return None, response.response_code, response.response_message
        else:
            try:
                precommit_block = self.__blockchain.block_loads(response.block)
            except Exception as e:
                traceback.print_exc()
                raise exception.BlockError(f"Received block is invalid: original exception={e}")
            # util.logger.spam(
            #     f"GetPrecommitBlock:response::{response.response_code}/{response.response_message}/"
            #     f"{precommit_block}/{precommit_block.confirmed_transaction_list}")
            return precommit_block, response.response_code, response.response_message

    def __start_block_height_sync_timer(self):
        timer_key = TimerService.TIMER_KEY_BLOCK_HEIGHT_SYNC
        timer_service: TimerService = self.__channel_service.timer_service

        if timer_key not in timer_service.timer_list:
            util.logger.spam(f"add timer for block_request_call to radiostation...")
            timer_service.add_timer(
                timer_key,
                Timer(
                    target=timer_key,
                    duration=conf.GET_LAST_BLOCK_TIMER,
                    is_repeat=True,
                    callback=self.block_height_sync
                )
            )

    def stop_block_height_sync_timer(self):
        timer_key = TimerService.TIMER_KEY_BLOCK_HEIGHT_SYNC
        timer_service: TimerService = self.__channel_service.timer_service
        if timer_key in timer_service.timer_list:
            timer_service.stop_timer(timer_key)

    def start_block_generate_timer(self):
        timer_key = TimerService.TIMER_KEY_BLOCK_GENERATE
        timer_service: TimerService = self.__channel_service.timer_service

        if timer_key not in timer_service.timer_list:
            if self.__consensus_algorithm:
                self.__consensus_algorithm.stop()

        self.__consensus_algorithm = ConsensusSiever(self)
        self.__consensus_algorithm.start_timer(timer_service)

    def stop_block_generate_timer(self):
        if self.__consensus_algorithm:
            self.__consensus_algorithm.stop()

    def __current_block_height(self):
        if self.__blockchain.last_unconfirmed_block and \
                self.__blockchain.last_unconfirmed_block.header.height == self.__blockchain.block_height + 1:
            return self.__blockchain.block_height + 1
        else:
            return self.__blockchain.block_height

    def __current_last_block(self):
        return self.__blockchain.last_unconfirmed_block or self.__blockchain.last_block

    def __add_block_by_sync(self, block_, confirm_info=None):
        commit_state = block_.header.commit_state
        logging.debug(f"block_manager.py >> block_height_sync :: "
                      f"height({block_.header.height})")

        block_version = self.get_blockchain().block_versioner.get_version(block_.header.height)
        block_verifier = BlockVerifier.new(block_version, self.get_blockchain().tx_versioner)
        if block_.header.height == 0:
            block_verifier.invoke_func = self.__channel_service.genesis_invoke
        else:
            block_verifier.invoke_func = self.__channel_service.score_invoke

        reps = self.__channel_service.get_rep_ids()
        invoke_results = block_verifier.verify_loosely(block_,
                                                       self.__blockchain.last_block,
                                                       self.__blockchain,
                                                       reps=reps)
        self.__blockchain.set_invoke_results(block_.header.hash.hex(), invoke_results)
        return self.__blockchain.add_block(block_, confirm_info)

    def __confirm_prev_block_by_sync(self, block_):
        prev_block = self.__blockchain.last_unconfirmed_block
        confirm_info = block_.body.confirm_prev_block

        logging.debug(f"block_manager.py >> block_height_sync :: height({prev_block.header.height})")

        block_version = self.get_blockchain().block_versioner.get_version(prev_block.header.height)
        block_verifier = BlockVerifier.new(block_version, self.get_blockchain().tx_versioner)
        if prev_block.header.height == 0:
            block_verifier.invoke_func = self.__channel_service.genesis_invoke
        else:
            block_verifier.invoke_func = self.__channel_service.score_invoke

        reps = self.__channel_service.get_rep_ids()
        invoke_results = block_verifier.verify_loosely(prev_block,
                                                       self.__blockchain.last_block,
                                                       self.__blockchain,
                                                       reps=reps)
        self.__blockchain.set_invoke_results(prev_block.header.hash.hex(), invoke_results)
        return self.__blockchain.add_block(prev_block, confirm_info)

    def __block_request_to_peers_in_sync(self, peer_stubs, my_height, unconfirmed_block_height, max_height):
        """Extracted func from __block_height_sync.
        It has block request loop with peer_stubs for block height sync.

        :param peer_stubs:
        :param my_height:
        :param unconfirmed_block_height:
        :param max_height:
        :return: my_height, max_height
        """
        peer_stubs_len = len(peer_stubs)
        peer_index = 0
        retry_number = 0

        while max_height > my_height:
            peer_stub = peer_stubs[peer_index]
            try:
                block, max_block_height, current_unconfirmed_block_height, confirm_info, response_code = \
                    self.__block_request(peer_stub, my_height + 1)
            except Exception as e:
                logging.warning("There is a bad peer, I hate you: " + str(e))
                traceback.print_exc()
                response_code = message_code.Response.fail

            if response_code == message_code.Response.success:
                logging.debug(f"try add block height: {block.header.height}")

                max_block_height = max(max_block_height, current_unconfirmed_block_height)
                if max_block_height > max_height:
                    util.logger.spam(f"set max_height :{max_height} -> {max_block_height}")
                    max_height = max_block_height
                    if current_unconfirmed_block_height == max_block_height:
                        unconfirmed_block_height = current_unconfirmed_block_height

                try:
                    result = True
                    if max_height == unconfirmed_block_height == block.header.height \
                            and max_height > 0 and not confirm_info:
                        self.candidate_blocks.add_block(block)
                        self.__blockchain.last_unconfirmed_block = block
                        result = True
                    else:
                        result = self.__add_block_by_sync(block, confirm_info)

                    if result:
                        if block.header.height == 0:
                            self.__rebuild_nid(block)
                        elif self.__blockchain.find_nid() is None:
                            genesis_block = self.get_blockchain().find_block_by_height(0)
                            self.__rebuild_nid(genesis_block)

                except KeyError as e:
                    result = False
                    logging.error("fail block height sync: " + str(e))
                    break
                except exception.BlockError:
                    result = False
                    logging.error("Block Error Clear all block and restart peer.")
                    self.clear_all_blocks()
                    util.exit_and_msg("Block Error Clear all block and restart peer.")
                    break
                finally:
                    peer_index = (peer_index + 1) % peer_stubs_len
                    if result:
                        my_height += 1
                        retry_number = 0
                    else:
                        retry_number += 1
                        logging.warning(f"Block height({my_height}) synchronization is fail. "
                                        f"{retry_number}/{conf.BLOCK_SYNC_RETRY_NUMBER}")
                        if retry_number >= conf.BLOCK_SYNC_RETRY_NUMBER:
                            util.exit_and_msg(f"This peer already tried to synchronize {my_height} block "
                                              f"for max retry number({conf.BLOCK_SYNC_RETRY_NUMBER}). "
                                              f"Peer will be down.")
            else:
                logging.warning(f"Not responding peer({peer_stub}) is removed from the peer stubs target.")
                if peer_stubs_len == 1:
                    raise ConnectionError
                del peer_stubs[peer_index]
                peer_stubs_len -= 1
                peer_index %= peer_stubs_len  # If peer_index is last index, go to first

        return my_height, max_height

    def __block_height_sync(self):
        # Make Peer Stub List [peer_stub, ...] and get max_height of network
        max_height, unconfirmed_block_height, peer_stubs = self.__get_peer_stub_list()

        if self.__blockchain.last_unconfirmed_block is not None:
            self.candidate_blocks.remove_block(self.__blockchain.last_unconfirmed_block.header.hash)
        self.__blockchain.last_unconfirmed_block = None

        my_height = self.__current_block_height()
        logging.debug(f"in __block_height_sync max_height({max_height}), my_height({my_height})")

        self.get_blockchain().prevent_next_block_mismatch(self.__blockchain.block_height)

        try:
            if peer_stubs:
                my_height, max_height = self.__block_request_to_peers_in_sync(peer_stubs,
                                                                              my_height,
                                                                              unconfirmed_block_height,
                                                                              max_height)
        except Exception as e:
            logging.warning(f"block_manager.py >>> block_height_sync :: {e}")
            traceback.print_exc()
            self.__start_block_height_sync_timer()
            return False

        if my_height >= max_height:
            util.logger.debug(f"block_manager:block_height_sync is complete.")
            next_leader = self.__current_last_block().header.next_leader
            leader_peer = self.__channel_service.peer_manager.get_peer(next_leader.hex_hx()) if next_leader else None

            if self.epoch.height < my_height:
                self.epoch = Epoch.new_epoch()

            if leader_peer:
                self.__channel_service.peer_manager.set_leader_peer(leader_peer, None)
                self.epoch = Epoch.new_epoch(leader_peer.peer_id)
            self.__channel_service.state_machine.complete_sync()
        else:
            logging.warning(f"it's not completed block height synchronization in once ...\n"
                            f"try block_height_sync again... my_height({my_height}) in channel({self.__channel_name})")
            self.__channel_service.state_machine.block_sync()

        return True

    def __get_peer_stub_list(self):
        """It updates peer list for block manager refer to peer list on the loopchain network.
        This peer list is not same to the peer list of the loopchain network.

        :return max_height: a height of current blockchain
        :return peer_stubs: current peer list on the loopchain network
        """
        max_height = -1      # current max height
        unconfirmed_block_height = -1
        peer_stubs = []     # peer stub list for block height synchronization

        if not ObjectManager().channel_service.is_support_node_function(conf.NodeFunction.Vote):
            rest_stub = ObjectManager().channel_service.radio_station_stub
            peer_stubs.append(rest_stub)
            response = rest_stub.call("Status")
            height_from_status = int(json.loads(response.text)["block_height"])
            last_height = rest_stub.call("GetLastBlock").get('height')
            logging.debug(f"last_height: {last_height}, height_from_status: {height_from_status}")
            max_height = max(height_from_status, last_height)
            unconfirmed_block_height = int(
                json.loads(response.text).get("unconfirmed_block_height", -1)
            )
            return max_height, unconfirmed_block_height, peer_stubs

        # Make Peer Stub List [peer_stub, ...] and get max_height of network
        peer_target = ChannelProperty().peer_target
        peer_manager = ObjectManager().channel_service.peer_manager
        target_dict = peer_manager.get_IP_of_peers_dict()
        target_list = [peer_target for peer_id, peer_target in target_dict.items()
                       if peer_id != ChannelProperty().peer_id]

        for target in target_list:
            if target != peer_target:
                logging.debug(f"try to target({target})")
                channel = GRPCHelper().create_client_channel(target)
                stub = loopchain_pb2_grpc.PeerServiceStub(channel)
                try:
                    response = stub.GetStatus(loopchain_pb2.StatusRequest(
                        request="",
                        channel=self.__channel_name,
                    ), conf.GRPC_TIMEOUT_SHORT)

                    response.block_height = max(response.block_height, response.unconfirmed_block_height)

                    if response.block_height > max_height:
                        # Add peer as higher than this
                        max_height = response.block_height
                        unconfirmed_block_height = response.unconfirmed_block_height
                        peer_stubs.append(stub)

                except Exception as e:
                    logging.warning(f"This peer has already been removed from the block height target node. {e}")

        return max_height, unconfirmed_block_height, peer_stubs

    def __close_level_db(self):
        del self.__level_db
        self.__level_db = None
        self.__blockchain.close_blockchain_db()

    def stop(self):
        # for reuse level db when restart channel.
        self.__close_level_db()

        if conf.ALLOW_MAKE_EMPTY_BLOCK:
            self.__block_generation_scheduler.stop()

        if self.consensus_algorithm:
            self.consensus_algorithm.stop()

    def add_complain(self, complained_leader_id, new_leader_id, block_height, peer_id, group_id):
        if new_leader_id == self.epoch.leader_id:
            util.logger.info(f"Complained new leader is current leader({new_leader_id})")
            return

        if self.epoch.height == block_height:
            self.epoch.add_complain(complained_leader_id, new_leader_id, block_height, peer_id, group_id)

            elected_leader = self.epoch.complain_result()
            if elected_leader:
                self.__channel_service.reset_leader(elected_leader, complained=True)
                self.__channel_service.reset_leader_complain_timer()
        elif self.epoch.height < block_height:
            self.__channel_service.state_machine.block_sync()

    def leader_complain(self):
        # util.logger.notice(f"do leader complain.")
        new_leader_id = self.epoch.pop_complained_candidate_leader()
        complained_leader_id = self.epoch.leader_id

        if not new_leader_id:
            new_leader = self.__channel_service.peer_manager.get_next_leader_peer(
                current_leader_peer_id=complained_leader_id
            )
            new_leader_id = new_leader.peer_id if new_leader else None

            if not isinstance(new_leader_id, str):
                new_leader_id = ""

        if not isinstance(complained_leader_id, str):
            complained_leader_id = ""

        self.add_complain(
            complained_leader_id, new_leader_id, self.epoch.height, self.__peer_id, ChannelProperty().group_id
        )

        request = loopchain_pb2.ComplainLeaderRequest(
            complained_leader_id=complained_leader_id,
            channel=self.channel_name,
            new_leader_id=new_leader_id,
            block_height=self.epoch.height,
            message="I'm your father.",
            peer_id=self.__peer_id,
            group_id=ChannelProperty().group_id
        )

        util.logger.debug(f"leader complain "
                          f"complained_leader_id({complained_leader_id}), "
                          f"new_leader_id({new_leader_id})")

        self.__channel_service.broadcast_scheduler.schedule_broadcast("ComplainLeader", request)

    def vote_unconfirmed_block(self, block_hash, is_validated):
        logging.debug(f"block_manager:vote_unconfirmed_block ({self.channel_name}/{is_validated})")

        if is_validated:
            vote_code, message = message_code.get_response(message_code.Response.success_validate_block)
        else:
            vote_code, message = message_code.get_response(message_code.Response.fail_validate_block)

        block_vote = loopchain_pb2.BlockVote(
            vote_code=vote_code,
            channel=self.channel_name,
            message=message,
            block_hash=block_hash,
            peer_id=self.__peer_id,
            group_id=ChannelProperty().group_id)

        self.candidate_blocks.add_vote(
            block_hash,
            ChannelProperty().group_id,
            ChannelProperty().peer_id,
            is_validated
        )
        self.__channel_service.broadcast_scheduler.schedule_broadcast("VoteUnconfirmedBlock", block_vote)

    def __validate_unconfirmed_block_height(self, unconfirmed_block: Block):
        my_height = self.__blockchain.block_height
        if my_height < (unconfirmed_block.header.height - 2):
            self.__channel_service.state_machine.block_sync()
            raise BlockchainError(f"trigger block sync in _vote my_height({my_height}), "
                                  f"unconfirmed_block.header.height({unconfirmed_block.header.height})")

        # a block is already added that same height unconfirmed_block height
        if my_height >= unconfirmed_block.header.height:
            raise BlockchainError(f"block is already added my_height({my_height}), "
                                  f"unconfirmed_block.header.height({unconfirmed_block.header.height})")

    async def _vote(self, unconfirmed_block: Block):
        exc = None
        try:
            block_version = self.__blockchain.block_versioner.get_version(unconfirmed_block.header.height)
            block_verifier = BlockVerifier.new(block_version, self.__blockchain.tx_versioner)
            block_verifier.invoke_func = self.__channel_service.score_invoke
            reps = self.__channel_service.get_rep_ids()
            invoke_results = block_verifier.verify(unconfirmed_block,
                                                   self.__blockchain.last_block,
                                                   self.__blockchain,
                                                   self.__blockchain.last_block.header.next_leader,
                                                   reps=reps)
        except Exception as e:
            exc = e
            logging.error(e)
            traceback.print_exc()
        else:
            self.set_invoke_results(unconfirmed_block.header.hash.hex(), invoke_results)
            self.candidate_blocks.add_block(unconfirmed_block)
        finally:
            self.vote_unconfirmed_block(unconfirmed_block.header.hash, exc is None)

    async def vote_as_peer(self, unconfirmed_block: Block):
        """Vote to AnnounceUnconfirmedBlock
        """
        util.logger.debug(f"in vote_as_peer "
                          f"height({unconfirmed_block.header.height}) "
                          f"unconfirmed_block({unconfirmed_block.header.hash.hex()})")

        try:
            self.__validate_unconfirmed_block_height(unconfirmed_block)
        except BlockchainError as e:
            util.logger.debug(e)
            return

        try:
            self.add_unconfirmed_block(unconfirmed_block)
        except InvalidUnconfirmedBlock as e:
            util.logger.warning(e)
        except DuplicationUnconfirmedBlock as e:
            util.logger.debug(e)
            await self._vote(unconfirmed_block)
        else:
            await self._vote(unconfirmed_block)
            self.__channel_service.reset_leader(unconfirmed_block.header.next_leader.hex_hx())

        self.__channel_service.start_leader_complain_timer_if_tx_exists()
