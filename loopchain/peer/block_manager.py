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
import queue
import shutil
import traceback
from concurrent.futures import ThreadPoolExecutor, Future

from jsonrpcclient.exceptions import ReceivedErrorResponse

from loopchain.baseservice import BroadcastCommand, TimerService
from loopchain.consensus import *
from loopchain.peer import status_code
from loopchain.peer.candidate_blocks import CandidateBlocks
from loopchain.protos import loopchain_pb2_grpc
from loopchain.tools.grpc_helper import GRPCHelper
from loopchain.utils.message_queue import StubCollection

# Changing the import location will cause a pickle error.
import loopchain_pb2


class BlockManager(Subscriber):
    """P2P Service 를 담당하는 BlockGeneratorService, PeerService 와 분리된
    Thread 로 BlockChain 을 관리한다.
    BlockGenerator 의 BlockManager 는 주기적으로 Block 을 생성하여 Peer 로 broadcast 한다.
    Peer 의 BlockManager 는 전달 받은 Block 을 검증 처리 한다.
    """

    MAINNET = "cf43b3fd45981431a0e64f79d07bfcf703e064b73b802c5f32834eec72142190"
    TESTNET = "885b8021826f7e741be7f53bb95b48221e9ab263f377e997b2e47a7b8f4a2a8b"

    def __init__(self, channel_manager, peer_id, channel_name, level_db_identity):
        self.__channel_service = channel_manager
        self.__channel_name = channel_name
        self.__pre_validate_strategy = None
        self.__set_send_tx_type(conf.CHANNEL_OPTION[channel_name]["send_tx_type"])
        self.__peer_id = peer_id
        self.__level_db = None
        self.__level_db_path = ""
        self.__level_db, self.__level_db_path = util.init_level_db(
            level_db_identity=f"{level_db_identity}_{channel_name}",
            allow_rename_path=False
        )
        self.__txQueue = AgingCache(max_age_seconds=conf.MAX_TX_QUEUE_AGING_SECONDS,
                                    default_item_status=TransactionStatusInQueue.normal)
        self.__unconfirmedBlockQueue = queue.Queue()
        self.__candidate_blocks = None
        self.__candidate_blocks = CandidateBlocks(peer_id, channel_name)
        self.__blockchain = BlockChain(self.__level_db, channel_name)
        self.__peer_type = None
        self.__block_type = BlockType.general
        self.__consensus = None
        self.__consensus_algorithm = None
        self.__block_height_sync_lock = threading.Lock()
        self.__block_height_thread_pool = ThreadPoolExecutor(1, 'BlockHeightSyncThread')
        self.__block_height_future: Future = None
        self.__subscribe_target_peer_stub = None
        self.__block_generation_scheduler = BlockGenerationScheduler(self.__channel_name)
        self.__prev_epoch: Epoch = None
        self.__precommit_block: Block = None
        self.__epoch: Epoch = None
        self._event_list = [(Consensus.EVENT_COMPLETE_CONSENSUS, self.callback_complete_consensus)]
        self.set_peer_type(loopchain_pb2.PEER)
        self.name = "loopchain.peer.BlockManager"
        self.__service_status = status_code.Service.online

    def __set_send_tx_type(self, send_tx_type):
        if send_tx_type == conf.SendTxType.icx:
            self.__pre_validate_strategy = self.__pre_validate
        else:
            self.__pre_validate_strategy = self.__pre_validate_pass

    @property
    def channel_name(self):
        return self.__channel_name

    @property
    def service_status(self):
        # Return string for compatibility.
        if self.__service_status >= 0:
            return "Service is online: " + str(self.peer_type)
        else:
            return "Service is offline: " + status_code.get_status_reason(self.__service_status)

    def __update_service_status(self, status):
        self.__service_status = status
        StubCollection().peer_stub.sync_task().update_status(
            self.__channel_name,
            {"status": self.service_status})

    @property
    def peer_type(self):
        return self.__peer_type

    @property
    def consensus(self):
        return self.__consensus

    @consensus.setter
    def consensus(self, consensus: Consensus):
        self.__consensus = consensus

    @property
    def consensus_algorithm(self):
        return self.__consensus_algorithm

    @consensus_algorithm.setter
    def consensus_algorithm(self, consensus_algorithm):
        self.__consensus_algorithm = consensus_algorithm

    @property
    def precommit_block(self):
        return self.__precommit_block

    @precommit_block.setter
    def precommit_block(self, block):
        self.__precommit_block = block

    @property
    def block_type(self):
        return self.__block_type

    @block_type.setter
    def block_type(self, block_type):
        self.__block_type = block_type

    @property
    def block_generation_scheduler(self):
        return self.__block_generation_scheduler

    @property
    def subscribe_target_peer_stub(self):
        return self.__subscribe_target_peer_stub

    def get_level_db(self):
        return self.__level_db

    def clear_all_blocks(self):
        logging.debug(f"clear level db({self.__level_db_path})")
        shutil.rmtree(self.__level_db_path)

    def set_peer_type(self, peer_type):
        self.__peer_type = peer_type

    def __create_block_generation_schedule(self):
        # util.logger.spam(f"__create_block_generation_schedule:: CREATE BLOCK GENERATION SCHEDULE")
        if conf.CONSENSUS_ALGORITHM == conf.ConsensusAlgorithm.lft:
            Schedule = namedtuple("Schedule", "callback kwargs")
            schedule = Schedule(self.__consensus_algorithm.consensus, {})
            self.__block_generation_scheduler.add_schedule(schedule)
        else:
            self.__consensus_algorithm.consensus()

    def set_invoke_results(self, block_hash, invoke_results):
        self.__blockchain.set_invoke_results(block_hash, invoke_results)

    def set_last_commit_state(self, block_height, commit_state):
        self.__blockchain.set_last_commit_state(block_height, commit_state)

    def get_total_tx(self):
        """
        블럭체인의 Transaction total 리턴합니다.

        :return: 블럭체인안의 transaction total count
        """
        return self.__blockchain.total_tx

    def get_blockchain(self):
        return self.__blockchain

    def get_candidate_blocks(self):
        return self.__candidate_blocks

    def pre_validate(self, tx: Transaction):
        return self.__pre_validate_strategy(tx)

    def __pre_validate(self, tx: Transaction):
        if tx.tx_hash in self.__txQueue:
            raise TransactionInvalidDuplicatedHash(tx.tx_hash)

        if not util.is_in_time_boundary(tx.get_timestamp(), conf.ALLOW_TIMESTAMP_BOUNDARY_SECOND):
            raise TransactionInvalidOutOfTimeBound(tx.tx_hash, tx.get_timestamp(), util.get_now_time_stamp())

    def __pre_validate_pass(self, tx: Transaction):
        pass

    def broadcast_send_unconfirmed_block(self, block_: Block):
        """생성된 unconfirmed block 을 피어들에게 broadcast 하여 검증을 요청한다.
        """
        logging.debug(f"BroadCast AnnounceUnconfirmedBlock...peers: "
                      f"{ObjectManager().channel_service.peer_manager.get_peer_count()}")

        # util.logger.spam(f'block_manager:zip_test num of tx is {block_.confirmed_tx_len}')
        block_dump = util.block_dumps(block_)
        if conf.ALLOW_MAKE_EMPTY_BLOCK or block_.confirmed_tx_len > 0:
            self.__blockchain.increase_made_block_count()

        ObjectManager().channel_service.broadcast_scheduler.schedule_broadcast(
            "AnnounceUnconfirmedBlock",
            loopchain_pb2.BlockSend(
                block=block_dump,
                channel=self.__channel_name))

    def broadcast_audience_set(self):
        """Check Broadcast Audience and Return Status

        """
        ObjectManager().channel_service.broadcast_scheduler.schedule_job(BroadcastCommand.STATUS, "audience set")

    def add_tx_obj(self, tx):
        """전송 받은 tx 를 Block 생성을 위해서 큐에 입력한다. load 하지 않은 채 입력한다.

        :param tx: transaction object
        """
        self.__txQueue[tx.tx_hash] = tx

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

    def confirm_block(self, block: Block):
        try:
            confirmed_block = self.__blockchain.confirm_block(block.prev_block_hash)
            self.__notify_new_block()

        except BlockchainError as e:
            logging.warning(f"BlockchainError while confirm_block({e}), retry block_height_sync")
            self.block_height_sync()

    def add_unconfirmed_block(self, unconfirmed_block):
        # siever 인 경우 블럭에 담긴 투표 결과를 이전 블럭에 반영한다.
        if conf.CONSENSUS_ALGORITHM == conf.ConsensusAlgorithm.siever:
            if unconfirmed_block.prev_block_confirm:
                # logging.debug(f"block confirm by siever: "
                #               f"hash({unconfirmed_block.prev_block_hash}) "
                #               f"block.channel({unconfirmed_block.channel_name})")
                self.confirm_block(unconfirmed_block)
            elif unconfirmed_block.block_type is BlockType.peer_list:
                logging.debug(f"peer manager block confirm by siever: "
                              f"hash({unconfirmed_block.block_hash}) block.channel({unconfirmed_block.channel_name})")
                self.confirm_block(unconfirmed_block)
            else:
                # 투표에 실패한 블럭을 받은 경우
                # 특별한 처리가 필요 없다. 새로 받은 블럭을 아래 로직에서 add_unconfirm_block 으로 수행하면 된다.
                pass
        elif conf.CONSENSUS_ALGORITHM == conf.ConsensusAlgorithm.lft:
            if unconfirmed_block.prev_block_confirm:

                # turn off previous vote's timer when a general peer received new block for vote
                ObjectManager().peer_service.timer_service.stop_timer(unconfirmed_block.prev_block_hash)
                # logging.debug(f"block confirm by lft: "
                #               f"hash({unconfirmed_block.prev_block_hash}) "
                #               f"block.channel({unconfirmed_block.channel_name})")

                self.confirm_block(unconfirmed_block)
            elif unconfirmed_block.block_type is BlockType.peer_list:
                logging.debug(f"peer manager block confirm by lft: "
                              f"hash({unconfirmed_block.block_hash}) block.channel({unconfirmed_block.channel_name})")
                self.confirm_block(unconfirmed_block)
            else:
                # 투표에 실패한 블럭을 받은 경우
                # 특별한 처리가 필요 없다. 새로 받은 블럭을 아래 로직에서 add_unconfirm_block 으로 수행하면 된다.
                pass

        self.__unconfirmedBlockQueue.put(unconfirmed_block)

    def add_confirmed_block(self, confirmed_block: Block):
        is_commit_state_validation = False if not confirmed_block.commit_state else True
        result = self.__blockchain.add_block(confirmed_block, is_commit_state_validation)
        if not result:
            self.block_height_sync(target_peer_stub=ObjectManager().channel_service.radio_station_stub)

        self.__notify_new_block()

    def add_block(self, block_: Block, is_commit_state_validation=False) -> bool:
        """ add committed block

        :param block_: a block after confirmation
        :param is_commit_state_validation: if True: add only commit state validate pass
        :return: to add block is success or not
        """
        result = self.__blockchain.add_block(block_, is_commit_state_validation)

        last_block = self.__blockchain.last_block
        self.__notify_new_block()

        peer_id = ChannelProperty().peer_id
        util.apm_event(peer_id, {
            'event_type': 'TotalTx',
            'peer_id': peer_id,
            'peer_name': conf.PEER_NAME,
            'channel_name': self.__channel_name,
            'data': {
                'block_hash': block_.block_hash,
                'total_tx': self.__blockchain.total_tx}})

        return result

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
        if block.block_hash == BlockManager.MAINNET:
            nid = NID.mainnet.value
        elif block.block_hash == BlockManager.TESTNET:
            nid = NID.testnet.value
        elif block.confirmed_tx_len > 0:
            nid = block.confirmed_transaction_list[0].nid
            if nid is None:
                nid = NID.unknown.value

        self.get_blockchain().put_nid(nid)
        ChannelProperty().nid = nid

    def block_height_sync(self, target_peer_stub=None):
        with self.__block_height_sync_lock:
            need_to_sync = (self.__block_height_future is None or self.__block_height_future.done())

            if need_to_sync:
                self.__block_height_future = self.__block_height_thread_pool.submit(
                    self.__block_height_sync, target_peer_stub)
            else:
                logging.warning('Tried block_height_sync. But failed. The thread is already running')

            return need_to_sync, self.__block_height_future

    def __block_request(self, peer_stub, block_height):
        """request block by gRPC or REST

        :param peer_stub:
        :param block_height:
        :return block, max_block_height, response_code
        """
        if ObjectManager().channel_service.is_support_node_function(conf.NodeFunction.Vote):
            response = peer_stub.BlockSync(loopchain_pb2.BlockSyncRequest(
                block_height=block_height,
                channel=self.__channel_name
            ), conf.GRPC_TIMEOUT)
            return util.block_loads(response.block), response.max_block_height, response.response_code
        else:
            # request REST(json-rpc) way to radiostation (mother peer)
            return self.__block_request_by_citizen(block_height, ObjectManager().channel_service.radio_station_stub)

    def __block_request_by_citizen(self, block_height, rs_rest_stub):
        try:
            get_block_result = rs_rest_stub.call(
                "GetBlockByHeight", {
                    'channel': self.__channel_name,
                    'height': str(block_height)
                }
            )
            max_height_result = rs_rest_stub.call("Status")

            if max_height_result.status_code != 200:
                raise ConnectionError

            block_data_str = json.dumps(get_block_result['block'])
            block = Block(self.__channel_name)
            block.deserialize_block(block_data_str.encode('utf-8'))

            return block, json.loads(max_height_result.text)['block_height'], message_code.Response.success

        except ReceivedErrorResponse as e:
            rs_rest_stub.update_methods_version()
            return self.__block_request_by_citizen(block_height, rs_rest_stub)

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
            precommit_block = pickle.loads(response.block)
            # util.logger.spam(
            #     f"GetPrecommitBlock:response::{response.response_code}/{response.response_message}/"
            #     f"{precommit_block}/{precommit_block.confirmed_transaction_list}")
            return precommit_block, response.response_code, response.response_message

    def __start_block_height_sync_timer(self, target_peer_stub):
        timer_key = TimerService.TIMER_KEY_BLOCK_HEIGHT_SYNC
        timer_service: TimerService = self.__channel_service.timer_service

        if timer_key not in timer_service.timer_list.keys():
            util.logger.spam(f"add timer for block_request_call to radiostation...")
            timer_service.add_timer(
                timer_key,
                Timer(
                    target=timer_key,
                    duration=conf.GET_LAST_BLOCK_TIMER,
                    is_repeat=True,
                    callback=self.__block_height_sync,
                    callback_kwargs={'target_peer_stub': target_peer_stub}
                )
            )

    def __stop_block_height_sync_timer(self):
        timer_key = TimerService.TIMER_KEY_BLOCK_HEIGHT_SYNC
        timer_service: TimerService = self.__channel_service.timer_service
        if timer_key in timer_service.timer_list.keys():
            timer_service.stop_timer(timer_key)

    def start_block_generate_timer(self):
        timer_key = TimerService.TIMER_KEY_BLOCK_GENERATE
        timer_service: TimerService = self.__channel_service.timer_service

        if timer_key not in timer_service.timer_list.keys():
            util.logger.spam(f"add timer block generate")
            timer_service.add_timer(
                timer_key,
                Timer(
                    target=timer_key,
                    duration=conf.INTERVAL_BLOCKGENERATION,
                    is_repeat=True,
                    callback=self.__create_block_generation_schedule
                )
            )

    def stop_block_generate_timer(self):
        timer_key = TimerService.TIMER_KEY_BLOCK_GENERATE
        timer_service: TimerService = self.__channel_service.timer_service
        if timer_key in timer_service.timer_list.keys():
            timer_service.stop_timer(timer_key)

    def __block_height_sync(self, target_peer_stub=None, target_height=None):
        """synchronize block height with other peers"""
        self.__update_service_status(status_code.Service.block_height_sync)
        is_sync_complete = False

        try:
            channel_service = ObjectManager().channel_service
            peer_manager = channel_service.peer_manager

            if target_peer_stub is None:
                target_peer_stub = peer_manager.get_leader_stub_manager()
            self.__subscribe_target_peer_stub = target_peer_stub

            # The adjustment of block height and the process for data synchronization of peer
            # === Love&Hate Algorithm === #
            logging.info("try block height sync...with love&hate")

            # Make Peer Stub List [peer_stub, ...] and get max_height of network
            # max_height: current max height
            # peer_stubs: peer stub list for block height synchronization
            max_height, peer_stubs = self.__get_peer_stub_list(target_peer_stub)
            if target_height is not None:
                max_height = target_height

            my_height = self.__blockchain.block_height
            retry_number = 0
            util.logger.spam(f"block_manager:block_height_sync my_height({my_height})")

            if len(peer_stubs) == 0:
                util.logger.warning("peer_service:block_height_sync there is no other peer to height sync!")
                return False
            else:
                self.__stop_block_height_sync_timer()

            logging.info(f"You need block height sync to: {max_height} yours: {my_height}")

            while max_height > my_height:
                for peer_stub in peer_stubs:
                    response_code = message_code.Response.fail
                    try:
                        block, max_block_height, response_code = self.__block_request(peer_stub, my_height + 1)
                    except Exception as e:
                        logging.warning("There is a bad peer, I hate you: " + str(e))

                    if response_code == message_code.Response.success:
                        logging.debug(f"try add block height: {block.height}")

                        try:
                            result = False
                            commit_state = getattr(block, "_Block__commit_state", None)
                            logging.debug(f"block_manager.py >> block_height_sync :: "
                                          f"height({block.height}) commit_state({commit_state})")
                            result = self.add_block(
                                block_=block,
                                is_commit_state_validation=True if commit_state else False)

                            if result:
                                if block.height == 0:
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
                            if result:
                                my_height = block.height
                                retry_number = 0
                            else:
                                retry_number += 1
                                logging.warning(f"Block height({my_height}) synchronization is fail. "
                                                f"{retry_number}/{conf.BLOCK_SYNC_RETRY_NUMBER}")
                                if retry_number >= conf.BLOCK_SYNC_RETRY_NUMBER:
                                    util.exit_and_msg(f"This peer already tried to synchronize {my_height} block "
                                                      f"for max retry number({conf.BLOCK_SYNC_RETRY_NUMBER}). "
                                                      f"Peer will be down.")

                        if target_height is None:
                            if max_block_height > max_height:
                                util.logger.spam(f"set max_height :{max_height} -> {max_block_height}")
                                max_height = max_block_height
                    else:
                        peer_stubs.remove(peer_stub)
                        logging.warning(f"Not responding peer({peer_stub}) is removed from the peer stubs target.")

                        if len(peer_stubs) < 1:
                            raise ConnectionError

            if my_height >= max_height:
                is_sync_complete = True
                self.__channel_service.state_machine.subscribe_network()
        except Exception as e:
            logging.warning(f"block_manager.py >>> block_height_sync :: {e}")
            traceback.print_exc()
            self.__start_block_height_sync_timer(target_peer_stub)
            return False

        if not is_sync_complete:
            logging.warning(f"it's not completed block height synchronization in once ...\n"
                            f"try block_height_sync again... my_height({my_height}) in channel({self.__channel_name})")
            self.__channel_service.state_machine.block_sync()

        if conf.CONSENSUS_ALGORITHM == conf.ConsensusAlgorithm.lft \
                and channel_service.is_support_node_function(conf.NodeFunction.Vote):
            last_block = self.__blockchain.last_block
            precommit_block = None
            for peer_stub in peer_stubs:
                if peer_stub is not None:
                    precommit_block, response_code, response_message = \
                        self.__precommit_block_request(peer_stub, last_block.height)
                    util.logger.spam(f"block_manager:block_height_sync::precommit_block("
                                     f"{precommit_block if precommit_block else None})")
                    break

            if precommit_block:
                if last_block.height + 1 == precommit_block.height:
                    self.__blockchain.invoke_for_precommit(precommit_block)
                    self.__channel_service.score_write_precommit_state(precommit_block)
                    self.__blockchain.put_precommit_block(precommit_block)
                    self.__precommit_block = precommit_block
                    self.consensus.leader_id = precommit_block.peer_id
                    self.consensus.precommit_block = None
                    util.logger.spam(f"set precommit bock {self.__precommit_block.block_hash}/"
                                     f"{self.__precommit_block.height} after block height synchronization.")
                    self.__consensus.change_epoch(prev_epoch=None, precommit_block=self.__precommit_block)
                else:
                    util.logger.warning(f"precommit block is weird, an expected block height is {last_block.height+1}, "
                                        f"but it's {precommit_block.height}")

            else:
                util.logger.spam(f"precommit bock is None after block height synchronization.")

        logging.debug(f"block_manager:block_height_sync is complete.")
        self.__update_service_status(status_code.Service.online)

        return True

    def __notify_new_block(self):
        self.__channel_service.inner_service.notify_new_block()

    def __get_peer_stub_list(self, target_peer_stub=None):
        """It updates peer list for block manager refer to peer list on the loopchain network.
        This peer list is not same to the peer list of the loopchain network.

        :return max_height: a height of current blockchain
        :return peer_stubs: current peer list on the loopchain network
        """
        peer_target = ChannelProperty().peer_target
        peer_manager = ObjectManager().channel_service.peer_manager

        # Make Peer Stub List [peer_stub, ...] and get max_height of network
        max_height = -1      # current max height
        peer_stubs = []     # peer stub list for block height synchronization

        if ObjectManager().channel_service.is_support_node_function(conf.NodeFunction.Vote):
            target_dict = peer_manager.get_IP_of_peers_dict()
            target_list = [peer_target for peer_id, peer_target in target_dict.items()
                           if peer_id != ChannelProperty().peer_id]
        else:
            target_list = [f"{target_peer_stub.target}"]

        for target in target_list:
            if target != peer_target:
                logging.debug(f"try to target({target})")
                channel = GRPCHelper().create_client_channel(target)
                stub = loopchain_pb2_grpc.PeerServiceStub(channel)
                try:
                    if ObjectManager().channel_service.is_support_node_function(conf.NodeFunction.Vote):
                        response = stub.GetStatus(loopchain_pb2.StatusRequest(
                            request="",
                            channel=self.__channel_name,
                        ), conf.GRPC_TIMEOUT_SHORT)
                    else:
                        response = target_peer_stub.call("Status")
                        util.logger.spam('{/api/v1/status/peer} response: ' + response.text)
                        response.block_height = int(json.loads(response.text)["block_height"])
                        stub.target = target

                    if response.block_height > max_height:
                        # Add peer as higher than this
                        max_height = response.block_height
                        peer_stubs.append(stub)

                except Exception as e:
                    logging.warning(f"This peer has already been removed from the block height target node. {e}")

        return max_height, peer_stubs

    def __close_level_db(self):
        del self.__level_db
        self.__level_db = None
        self.__blockchain.close_blockchain_db()

    def stop(self):
        # for reuse level db when restart channel.
        self.__close_level_db()

        if conf.ALLOW_MAKE_EMPTY_BLOCK:
            self.__block_generation_scheduler.stop()
        CommonThread.stop(self)

    def __vote_unconfirmed_block(self, block_hash, is_validated):
        logging.debug(f"block_manager:__vote_unconfirmed_block ({self.channel_name}/{is_validated})")

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

        self.__channel_service.broadcast_scheduler.schedule_broadcast("VoteUnconfirmedBlock", block_vote)

    def vote_as_peer(self):
        """Vote to AnnounceUnconfirmedBlock
        """
        if not self.__unconfirmedBlockQueue.empty():
            unconfirmed_block = self.__unconfirmedBlockQueue.get()
            logging.debug(f"we got unconfirmed block ....{unconfirmed_block.block_hash}")
        else:
            time.sleep(conf.SLEEP_SECONDS_IN_SERVICE_LOOP)
            # logging.debug("No unconfirmed block ....")
            return

        my_height = self.__blockchain.block_height
        if my_height < (unconfirmed_block.height - 1):
            self.__channel_service.state_machine.block_sync()
            return

        # a block is already added that same height unconfirmed_block height
        if my_height >= unconfirmed_block.height:
            return

        logging.info("PeerService received unconfirmed block: " + unconfirmed_block.block_hash)

        if unconfirmed_block.confirmed_tx_len == 0 \
                and unconfirmed_block.block_type is not BlockType.peer_list \
                and not conf.ALLOW_MAKE_EMPTY_BLOCK:
            # "VOTE Block" has no tx. (no need validate and vote to block)
            # logging.warning("This is vote block by siever")
            pass
        else:
            # block validate
            block_is_validated = False
            try:
                block_is_validated = Block.validate(unconfirmed_block)

                if conf.CHANNEL_OPTION[self.__channel_name]['store_valid_transaction_only']:
                    block_is_validated, need_rebuild, invoke_results = unconfirmed_block.verify_through_score_invoke()
                    self.set_invoke_results(unconfirmed_block.block_hash, invoke_results)

            except Exception as e:
                logging.error(e)

            if block_is_validated:
                # broadcast 를 받으면 받은 블럭을 검증한 후 검증되면 자신의 blockchain 의 unconfirmed block 으로 등록해 둔다.
                confirmed, reason = self.__blockchain.add_unconfirm_block(unconfirmed_block)
                if confirmed:
                    # block is confirmed
                    # validated 일 때 투표 할 것이냐? confirmed 일 때 투표할 것이냐? 현재는 validate 만 체크
                    pass
                elif reason == "block_height":
                    pass
                    # Announce 되는 블럭과 자신의 height 가 다르면 Block Height Sync 를 다시 시도한다.
                    # self.block_height_sync()

            self.__vote_unconfirmed_block(unconfirmed_block.block_hash, block_is_validated)

    def callback_complete_consensus(self, **kwargs):
        self.__prev_epoch = kwargs.get("prev_epoch", None)
        self.__epoch = kwargs.get("epoch", None)
        last_block = self.get_blockchain().last_block
        last_block_height = last_block.height

        if last_block_height > 0 and self.__precommit_block is None:
            logging.error("It's weird what a precommit block is None. "
                          "That's why a timer can't be added to timer service.")

        if self.__prev_epoch:
            if self.__prev_epoch.status == EpochStatus.success:
                util.logger.spam(f"BlockManager:callback_complete_consensus::epoch status is success !! "
                                 f"self.__precommit_block({self.__precommit_block})")

                if self.__precommit_block:
                    if not self.add_block(self.__precommit_block):
                        self.__precommit_block = self.__blockchain.get_precommit_block()

                self.__precommit_block = kwargs.get("precommit_block", None)
                if self.__channel_service.score_write_precommit_state(self.__precommit_block) and \
                        self.__blockchain.put_precommit_block(self.__precommit_block):
                    util.logger.spam(f"start timer :: success precommit block info - {self.__precommit_block.height}")

            elif self.__prev_epoch.status == EpochStatus.leader_complain:
                self.__epoch.fixed_vote_list = self.__prev_epoch.ready_vote_list
                self.__precommit_block = self.__consensus.precommit_block
                self.__prev_epoch = self.__prev_epoch.prev_epoch
                util.logger.spam(f"start timer :: fail precommit block info - {self.__precommit_block.height}")

            self.__channel_service.consensus.start_timer(self.__channel_service.acceptor.callback_leader_complain)
        else:
            util.logger.spam(f"start timer :: after genesis or rebuild block / "
                             f"precommit block info - {last_block_height}")
