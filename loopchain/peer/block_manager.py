"""A management class for blockchain."""

import asyncio
import json
import re
import threading
import traceback
from collections import defaultdict, OrderedDict
from concurrent.futures import ThreadPoolExecutor, Future
from typing import TYPE_CHECKING, Dict, DefaultDict, Optional, Tuple, List, Union, Set, Coroutine, Any, cast

from pkg_resources import parse_version

import loopchain.utils as util
from loopchain import configure as conf
from loopchain.baseservice import TimerService, ObjectManager, Timer, RestMethod
from loopchain.baseservice.aging_cache import AgingCache
from loopchain.baseservice.rest_client import RestClient
from loopchain.blockchain import (BlockChain, CandidateBlocks, Epoch, BlockchainError, NID, exception, NoConfirmInfo,
                                  BlockHeightMismatch, RoundMismatch)
from loopchain.blockchain.blocks import Block, BlockVerifier, BlockSerializer
from loopchain.blockchain.blocks.block import NextRepsChangeReason
from loopchain.blockchain.exception import (ConfirmInfoInvalid, ConfirmInfoInvalidAddedBlock, NotInReps,
                                            NotReadyToConfirmInfo, UnrecordedBlock, UnexpectedLeader)
from loopchain.blockchain.exception import ConfirmInfoInvalidNeedBlockSync, TransactionDuplicatedHashError
from loopchain.blockchain.exception import InvalidUnconfirmedBlock, DuplicationUnconfirmedBlock, ScoreInvokeError
from loopchain.blockchain.transactions import Transaction, TransactionSerializer, v2, v3
from loopchain.blockchain.types import ExternalAddress
from loopchain.blockchain.types import TransactionStatusInQueue, Hash32
from loopchain.blockchain.votes import Vote, Votes
from loopchain.blockchain.votes.v0_5 import LeaderVote
from loopchain.channel.channel_property import ChannelProperty
from loopchain.jsonrpc import GenericJsonRpcServerError
from loopchain.peer import status_code
from loopchain.peer.consensus_siever import ConsensusSiever
from loopchain.protos import loopchain_pb2, loopchain_pb2_grpc, message_code
from loopchain.tools.grpc_helper import GRPCHelper
from loopchain.utils.icon_service import convert_params, ParamType, response_to_json_query
from loopchain.utils.message_queue import StubCollection

if TYPE_CHECKING:
    from loopchain.channel.channel_service import ChannelService

RequestResult = Tuple[Block, int, int, Union[List, bytes], int]


class BlockManager:
    """Manage the blockchain of a channel. It has objects for consensus and db object.
    """

    MAINNET = "cf43b3fd45981431a0e64f79d07bfcf703e064b73b802c5f32834eec72142190"
    TESTNET = "885b8021826f7e741be7f53bb95b48221e9ab263f377e997b2e47a7b8f4a2a8b"

    def __init__(self, channel_service: 'ChannelService', peer_id: str, channel_name: str, store_id: str):
        self.__channel_service: ChannelService = channel_service
        self.__channel_name = channel_name
        self.__peer_id = peer_id

        self.__tx_queue = AgingCache(max_age_seconds=conf.MAX_TX_QUEUE_AGING_SECONDS,
                                     default_item_status=TransactionStatusInQueue.normal)
        self.blockchain = BlockChain(channel_name, store_id, self)
        self.__peer_type = None
        self.__consensus_algorithm = None
        self.candidate_blocks = CandidateBlocks(self.blockchain)
        self.__block_height_sync_bad_targets = {}
        self.__block_height_sync_lock = threading.Lock()
        self.__block_height_thread_pool: ThreadPoolExecutor = ThreadPoolExecutor(1, 'BlockHeightSyncThread')
        self.__block_height_future: Future = None
        self.set_peer_type(loopchain_pb2.PEER)
        self.__service_status = status_code.Service.online

        # old_block_hashes[height][new_block_hash] = old_block_hash
        self.__old_block_hashes: DefaultDict[int, Dict[Hash32, Hash32]] = defaultdict(dict)
        self.epoch: Epoch = None

        self._sync_request_result: Dict[int, asyncio.Future] = dict()
        self._sync_peer_target: Dict[int, str] = dict()
        self._request_limit_event: Optional[asyncio.Event] = None

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

    def update_service_status(self, status):
        self.__service_status = status

    @property
    def peer_type(self):
        return self.__peer_type

    @property
    def consensus_algorithm(self):
        return self.__consensus_algorithm

    def set_peer_type(self, peer_type):
        self.__peer_type = peer_type

    def set_old_block_hash(self, block_height: int, new_block_hash: Hash32, old_block_hash: Hash32):
        self.__old_block_hashes[block_height][new_block_hash] = old_block_hash

    def get_old_block_hash(self,  block_height: int, new_block_hash: Hash32):
        return self.__old_block_hashes[block_height][new_block_hash]

    def pop_old_block_hashes(self, block_height: int):
        self.__old_block_hashes.pop(block_height)

    def get_total_tx(self):
        """
        블럭체인의 Transaction total 리턴합니다.

        :return: 블럭체인안의 transaction total count
        """
        return self.blockchain.total_tx

    def broadcast_send_unconfirmed_block(self, block_: Block, round_: int):
        """broadcast unconfirmed block for getting votes form reps
        """
        last_block: Block = self.blockchain.last_block
        if (self.__channel_service.state_machine.state != "BlockGenerate" and
                last_block.header.height > block_.header.height):
            util.logger.debug(
                f"Last block has reached a sufficient height. Broadcast will stop! ({block_.header.hash.hex()})")
            ConsensusSiever.stop_broadcast_send_unconfirmed_block_timer()
            return

        if last_block.header.revealed_next_reps_hash:
            if block_.header.is_unrecorded:
                self._send_unconfirmed_block(block_, last_block.header.reps_hash, round_)
            else:
                self._send_unconfirmed_block(block_, block_.header.reps_hash, round_)
        else:
            self._send_unconfirmed_block(block_, ChannelProperty().crep_root_hash, round_)

    def _send_unconfirmed_block(self, block_: Block, target_reps_hash, round_: int):
        util.logger.debug(
            f"BroadCast AnnounceUnconfirmedBlock "
            f"height({block_.header.height}) round({round_}) block({block_.header.hash}) peers: "
            f"target_reps_hash({target_reps_hash})")

        block_dumped = self.blockchain.block_dumps(block_)
        send_kwargs = {
            "block": block_dumped,
            "round_": round_,
            "channel": self.__channel_name,
            "peer_id": block_.header.peer_id.hex_hx(),
            "height": block_.header.height,
            "hash": block_.header.hash.hex()
        }

        release_recovery_mode = False
        if conf.RECOVERY_MODE:
            from loopchain.tools.recovery import Recovery
            if self.blockchain.block_height <= Recovery.release_block_height():
                util.logger.info(f"broadcast block({block_.header.height}) from recovery node")
                send_kwargs.update({"from_recovery": True})

            if self.blockchain.block_height >= Recovery.release_block_height():
                release_recovery_mode = True

        self.__channel_service.broadcast_scheduler.schedule_broadcast(
            "AnnounceUnconfirmedBlock",
            loopchain_pb2.BlockSend(**send_kwargs),
            reps_hash=target_reps_hash
        )

        if release_recovery_mode:
            conf.RECOVERY_MODE = False
            util.logger.info(f"recovery mode released at {self.blockchain.block_height}")

    def add_tx_obj(self, tx):
        """전송 받은 tx 를 Block 생성을 위해서 큐에 입력한다. load 하지 않은 채 입력한다.

        :param tx: transaction object
        """
        self.__tx_queue[tx.hash.hex()] = tx

    def get_tx(self, tx_hash) -> Transaction:
        """Get transaction from block_db by tx_hash

        :param tx_hash: tx hash
        :return: tx object or None
        """
        return self.blockchain.find_tx_by_key(tx_hash)

    def get_tx_info(self, tx_hash) -> dict:
        """Get transaction info from block_db by tx_hash

        :param tx_hash: tx hash
        :return: {'block_hash': "", 'block_height': "", "transaction": "", "result": {"code": ""}}
        """
        return self.blockchain.find_tx_info(tx_hash)

    def get_invoke_result(self, tx_hash):
        """ get invoke result by tx

        :param tx_hash:
        :return:
        """
        return self.blockchain.find_invoke_result_by_tx_hash(tx_hash)

    def get_tx_queue(self):
        return self.__tx_queue

    def get_count_of_unconfirmed_tx(self):
        """BlockManager 의 상태를 확인하기 위하여 현재 입력된 unconfirmed_tx 의 카운트를 구한다.

        :return: 현재 입력된 unconfirmed tx 의 갯수
        """
        return len(self.__tx_queue)

    async def relay_all_txs(self):
        rs_client = ObjectManager().channel_service.rs_client
        if not rs_client:
            return

        items = list(self.__tx_queue.d.values())
        self.__tx_queue.d.clear()

        for item in items:
            tx = item.value
            if not util.is_in_time_boundary(tx.timestamp, conf.TIMESTAMP_BOUNDARY_SECOND, util.get_now_time_stamp()):
                continue

            ts = TransactionSerializer.new(tx.version, tx.type(), self.blockchain.tx_versioner)
            if tx.version == v2.version:
                rest_method = RestMethod.SendTransaction2
            elif tx.version == v3.version:
                rest_method = RestMethod.SendTransaction3
            else:
                continue

            raw_data = ts.to_raw_data(tx)
            raw_data["from_"] = raw_data.pop("from")
            for i in range(conf.RELAY_RETRY_TIMES):
                try:
                    await rs_client.call_async(rest_method,
                                               rest_method.value.params(**raw_data))
                except Exception as e:
                    util.logger.warning(f"Relay failed. Tx({tx}), {e!r}")
                else:
                    break

    def restore_tx_status(self, tx: Transaction):
        util.logger.debug(f"tx : {tx}")
        self.__tx_queue.set_item_status(tx.hash.hex(), TransactionStatusInQueue.normal)

    def __validate_duplication_of_unconfirmed_block(self, unconfirmed_block: Block):
        if self.blockchain.last_block.header.height >= unconfirmed_block.header.height:
            raise InvalidUnconfirmedBlock("The unconfirmed block has height already added.")

        try:
            candidate_block = self.candidate_blocks.blocks[unconfirmed_block.header.hash].block
        except KeyError:
            # When an unconfirmed block confirmed previous block, the block become last unconfirmed block,
            # But if the block is failed to verify, the block doesn't be added into candidate block.
            candidate_block: Block = self.blockchain.last_unconfirmed_block

        if candidate_block is None or unconfirmed_block.header.hash != candidate_block.header.hash:
            return

        raise DuplicationUnconfirmedBlock("Unconfirmed block has already been added.")

    def __validate_epoch_of_unconfirmed_block(self, unconfirmed_block: Block, round_: int):
        current_state = self.__channel_service.state_machine.state
        block_header = unconfirmed_block.header
        last_u_block = self.blockchain.last_unconfirmed_block

        if self.epoch.height == block_header.height and self.epoch.round < round_:
            raise InvalidUnconfirmedBlock(
                f"The unconfirmed block has invalid round. Expected({self.epoch.round}), Unconfirmed_block({round_})")

        if not self.epoch.complained_result:
            if last_u_block and (last_u_block.header.hash == block_header.hash or last_u_block.header.prep_changed):
                # TODO do not validate epoch in this case.
                expected_leader = block_header.peer_id.hex_hx()
            else:
                expected_leader = self.epoch.leader_id

            if expected_leader != block_header.peer_id.hex_hx():
                raise UnexpectedLeader(
                    f"The unconfirmed block({block_header.hash}) is made by an unexpected leader. "
                    f"Expected({expected_leader}), Unconfirmed_block({block_header.peer_id.hex_hx()})")

        if current_state == 'LeaderComplain' and self.epoch.leader_id == block_header.peer_id.hex_hx():
            raise InvalidUnconfirmedBlock(f"The unconfirmed block is made by complained leader.\n{block_header})")

    def add_unconfirmed_block(self, unconfirmed_block: Block, round_: int):
        """

        :param unconfirmed_block:
        :param round_:
        :return:
        """
        self.__validate_epoch_of_unconfirmed_block(unconfirmed_block, round_)
        self.__validate_duplication_of_unconfirmed_block(unconfirmed_block)

        last_unconfirmed_block: Block = self.blockchain.last_unconfirmed_block

        # TODO After the v0.4 update, remove this version parsing.
        if parse_version(unconfirmed_block.header.version) >= parse_version("0.4"):
            ratio = conf.VOTING_RATIO
        else:
            ratio = conf.LEADER_COMPLAIN_RATIO

        if unconfirmed_block.header.reps_hash:
            reps = self.blockchain.find_preps_addresses_by_roothash(unconfirmed_block.header.reps_hash)
            version = self.blockchain.block_versioner.get_version(unconfirmed_block.header.height)
            leader_votes = Votes.get_leader_votes_class(version)(
                reps,
                ratio,
                unconfirmed_block.header.height,
                None,
                unconfirmed_block.body.leader_votes
            )
            need_to_confirm = leader_votes.get_result() is None
        elif unconfirmed_block.body.confirm_prev_block:
            need_to_confirm = True
        else:
            need_to_confirm = False

        try:
            if need_to_confirm:
                self.blockchain.confirm_prev_block(unconfirmed_block)
                if unconfirmed_block.header.is_unrecorded:
                    self.blockchain.last_unconfirmed_block = None
                    raise UnrecordedBlock("It's an unnecessary block to vote.")
            elif last_unconfirmed_block is None:
                if self.blockchain.last_block.header.hash != unconfirmed_block.header.prev_hash:
                    raise BlockchainError(f"last block is not previous block. block={unconfirmed_block}")

                self.blockchain.last_unconfirmed_block = unconfirmed_block
        except BlockchainError as e:
            util.logger.warning(f"BlockchainError while confirm_block({e}), retry block_height_sync")
            self.__channel_service.state_machine.block_sync()
            raise InvalidUnconfirmedBlock(e)

    def add_confirmed_block(self, confirmed_block: Block, confirm_info=None):
        if self.__channel_service.state_machine.state != "Watch":
            util.logger.info(f"Can't add confirmed block if state is not Watch. {confirmed_block.header.hash.hex()}")
            return

        self.blockchain.add_block(confirmed_block, confirm_info=confirm_info)

    def rebuild_block(self):
        self.blockchain.rebuild_transaction_count()
        self.blockchain.rebuild_made_block_count()
        self.new_epoch()

        nid = self.blockchain.find_nid()
        if nid is None:
            genesis_block = self.blockchain.find_block_by_height(0)
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

        self.blockchain.put_nid(nid)
        ChannelProperty().nid = nid

    def block_height_sync(self):
        def _print_exception(fut):
            exc = fut.exception()
            if exc:
                traceback.print_exception(type(exc), exc, exc.__traceback__)

        with self.__block_height_sync_lock:
            need_to_sync = (self.__block_height_future is None or self.__block_height_future.done())

            if need_to_sync:
                self.__channel_service.stop_leader_complain_timer()
                self.__block_height_future = self.__block_height_thread_pool.submit(self._block_height_sync)
                self.__block_height_future.add_done_callback(_print_exception)
            else:
                util.logger.warning('Tried block_height_sync. But failed. The thread is already running')

            return need_to_sync, self.__block_height_future

    async def _citizen_request(self, block_height: int, max_height: int):
        request_coros: OrderedDict[int, Coroutine[int, int, RequestResult]] = OrderedDict()
        request_successes: Set[int] = set()
        request_height = block_height
        retry_time = 0

        while True:
            if max_height > request_height:
                request_height += 1
                request_coros[request_height] = self.__block_request_by_citizen(request_height, max_height)

            if max_height <= request_height or len(request_coros) == conf.CITIZEN_REQUEST_SIZE_CONCURRENTLY:
                util.logger.debug(f"request heights: {request_coros.keys()}, size: {len(request_coros)}")
                for done_future in asyncio.as_completed(request_coros.values()):
                    try:
                        request_result: RequestResult = await done_future
                    except Exception as e:
                        util.logging.exception(f"sync request failed caused by {e!r}")
                        response_code = message_code.Response.fail
                    else:
                        _block, _max_height, _unconfirmed_block_height, _, response_code = request_result
                        util.logger.debug(f"block_height({_block.header.height}) received")

                        result_future: asyncio.Future = self._sync_request_result.get(_block.header.height, None)
                        if result_future is None:
                            result_future = asyncio.get_event_loop().create_future()
                            self._sync_request_result[_block.header.height] = result_future
                        result_future.set_result(request_result)

                        max_block_height = max(_max_height, _unconfirmed_block_height)
                        if max_height < max_block_height:
                            max_height = max_block_height
                            util.logger.debug(f"new max_height : {max_height}")

                        request_successes.add(_block.header.height)

                    if response_code != message_code.Response.success:
                        retry_time += 1

                request_failed = set(request_coros.keys()) - request_successes
                if retry_time > conf.CITIZEN_ASYNC_REQUEST_RETRY_TIMES:
                    util.exit_and_msg(f"These heights({request_failed}) can't get Block Information.")

                request_coros.clear()

                # retry request at failed heights
                for retry_height in request_failed:
                    request_coros[retry_height] = self.__block_request_by_citizen(retry_height, max_height)

                if len(self._sync_request_result) >= conf.SYNC_REQUEST_RESULT_MAX_SIZE:
                    util.logger.debug(f"waiting on sync request size: {len(self._sync_request_result)}")
                    self._request_limit_event.clear()
                    await self._request_limit_event.wait()

            if request_height >= max_height and not request_coros:
                break

    async def _block_request(self, peer_stubs: List[Tuple], block_height: int, max_height: int):
        """request block by gRPC

        :param peer_stubs:
        :param block_height:
        :param max_height:
        :return
        """

        peer_index = 0
        origin_block_height = block_height

        while max_height > block_height:
            request_height = block_height + 1
            util.logger.debug(f"request_height : {request_height}")
            self._sync_peer_target[request_height], peer_stub = peer_stubs[peer_index]
            try:
                result_future = self._sync_request_result.get(request_height, None)
                if result_future is None:
                    result_future = asyncio.get_event_loop().create_future()
                    self._sync_request_result[request_height] = result_future

                # FIXME : block_request to asyncio_loop.run_in_executor
                request_result = self.__block_request_by_voter(request_height, peer_stub)
                result_future.set_result(request_result)

                _, _max_height, _unconfirmed_block_height, _, response_code = request_result
                max_block_height = max(_max_height, _unconfirmed_block_height)
                if max_height < max_block_height:
                    max_height = max_block_height
                    util.logger.debug(f"new max_height : {max_height}")

            except NoConfirmInfo as e:
                util.logger.warning(f"{e!r}")
                response_code = message_code.Response.fail_no_confirm_info
            except Exception as e:
                util.logger.exception(f"There is a bad peer: {e!r}")
                response_code = message_code.Response.fail

            if response_code == message_code.Response.success:
                if (len(peer_stubs) > 1 and
                        (request_height - origin_block_height) % conf.SYNC_BLOCK_COUNT_PER_NODE == 0):
                    peer_index = (peer_index + 1) % len(peer_stubs)

                    if len(self._sync_request_result) < conf.SYNC_REQUEST_RESULT_MAX_SIZE:
                        util.logger.debug(f"suspend on sync request size: {len(self._sync_request_result)}")
                        await asyncio.sleep(0)
                    else:
                        util.logger.debug(f"waiting event on sync request size: {len(self._sync_request_result)}")
                        self._request_limit_event.clear()
                        await self._request_limit_event.wait()
                block_height = request_height
            else:
                if len(peer_stubs) == 1:
                    raise ConnectionError

                peer_index = (peer_index + 1) % len(peer_stubs)

    def __block_request_by_voter(self, block_height, peer_stub) -> RequestResult:
        response = peer_stub.BlockSync(loopchain_pb2.BlockSyncRequest(
            block_height=block_height,
            channel=self.__channel_name
        ), conf.GRPC_TIMEOUT)

        if response.response_code == message_code.Response.fail_no_confirm_info:
            raise NoConfirmInfo(f"The peer has not confirm_info of the block by height({block_height}).")
        elif response.response_code in (message_code.Response.fail_not_enough_data,
                                        message_code.Response.fail_wrong_block_height):
            raise exception.BlockError(f"Received block is invalid: "
                                       f"response_message={message_code.get_response_msg(response.response_code)}")
        else:
            try:
                block = self.blockchain.block_loads(response.block)
            except Exception as e:
                traceback.print_exc()
                raise exception.BlockError(f"Received block is invalid: original exception={e}") from e

            votes_dumped: bytes = response.confirm_info
            try:
                votes_serialized = json.loads(votes_dumped)
                version = self.blockchain.block_versioner.get_version(block_height)
                votes = Votes.get_block_votes_class(version).deserialize_votes(votes_serialized)
            except json.JSONDecodeError:
                votes = votes_dumped

        return block, response.max_block_height, response.unconfirmed_block_height, votes, response.response_code

    async def __block_request_by_citizen(self, block_height: int, max_height: int) -> RequestResult:
        rs_client = ObjectManager().channel_service.rs_client
        get_block_result = await rs_client.call_async(
            RestMethod.GetBlockByHeight,
            RestMethod.GetBlockByHeight.value.params(height=str(block_height))
        )

        if max_height == block_height:
            last_block_height = self._get_last_block_height(rs_client)
            if last_block_height > max_height:
                max_height = last_block_height

        block_version = self.blockchain.block_versioner.get_version(block_height)
        block_serializer = BlockSerializer.new(block_version, self.blockchain.tx_versioner)
        block = block_serializer.deserialize(get_block_result['block'])
        votes_dumped: str = get_block_result.get('confirm_info', '')
        try:
            votes_serialized = json.loads(votes_dumped)
            version = self.blockchain.block_versioner.get_version(block_height)
            votes = Votes.get_block_votes_class(version).deserialize_votes(votes_serialized)
        except json.JSONDecodeError:
            votes = votes_dumped
        return block, max_height, -1, votes, message_code.Response.success

    def _get_last_block_height(self, rs_client):
        retry_count = 0

        max_height = -1
        while retry_count < conf.CITIZEN_ASYNC_REQUEST_RETRY_TIMES:
            last_block = rs_client.call(RestMethod.GetLastBlock)
            if not last_block:
                util.logging.warning("The Radiostation may not be ready. It will retry after a while.")
                retry_count += 1
            else:
                max_height = self.blockchain.block_versioner.get_height(last_block)
                break

        return max_height

    def __start_block_height_sync_timer(self, is_run_at_start=False):
        timer_key = TimerService.TIMER_KEY_BLOCK_HEIGHT_SYNC
        timer_service: TimerService = self.__channel_service.timer_service

        if timer_key not in timer_service.timer_list:
            util.logger.spam(f"add timer for block_request_call to radiostation...")
            timer_service.add_timer(
                timer_key,
                Timer(
                    target=timer_key,
                    duration=conf.GET_LAST_BLOCK_TIMER,
                    callback=self.block_height_sync,
                    is_repeat=True,
                    is_run_at_start=is_run_at_start
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

    async def _add_block_by_sync(self, block_, confirm_info: Optional[List] = None):
        """
        TODO : If possible, change _add_block_by_sync to coroutine

        :param block_:
        :param confirm_info:
        :return:
        """
        util.logger.debug(f"height({block_.header.height}) hash({block_.header.hash})")

        block_version = self.blockchain.block_versioner.get_version(block_.header.height)
        block_verifier = BlockVerifier.new(block_version, self.blockchain.tx_versioner, raise_exceptions=False)
        block_verifier.invoke_func = self.blockchain.get_invoke_func(block_.header.height)

        reps_getter = self.blockchain.find_preps_addresses_by_roothash
        block_verifier.verify_loosely(block_,
                                      self.blockchain.last_block,
                                      self.blockchain,
                                      reps_getter=reps_getter)
        need_to_write_tx_info, need_to_score_invoke = True, True
        for exc in block_verifier.exceptions:
            if isinstance(exc, TransactionDuplicatedHashError):
                need_to_write_tx_info = False
            if isinstance(exc, ScoreInvokeError) and not need_to_write_tx_info:
                need_to_score_invoke = False

        exc = next((exc for exc in block_verifier.exceptions
                    if not isinstance(exc, TransactionDuplicatedHashError)), None)
        if exc:
            if isinstance(exc, ScoreInvokeError) and not need_to_score_invoke:
                pass
            else:
                raise exc

        if parse_version(block_.header.version) >= parse_version("0.3"):
            reps = reps_getter(block_.header.reps_hash)
            round_ = next(vote for vote in confirm_info if vote).round
            votes = Votes.get_block_votes_class(block_.header.version)(
                reps,
                conf.VOTING_RATIO,
                block_.header.height,
                round_,
                block_.header.hash,
                confirm_info
            )
            votes.verify()
        return self.blockchain.add_block(block_, confirm_info, need_to_write_tx_info, need_to_score_invoke)

    async def _block_sync(self, peer_stubs: List, my_height: int, unconfirmed_block_height: int, max_height: int):
        """It has block request loop with peer_stubs for block height sync.

        :param peer_stubs:
        :param my_height:
        :param unconfirmed_block_height:
        :param max_height:
        :return: last_block_height, unconfirmed_block_height, max_height
        """
        while max_height > my_height:
            if self.__channel_service.state_machine.state != 'BlockSync':
                break

            sync_height = my_height + 1
            result_future = self._sync_request_result.get(sync_height, None)
            if result_future is None:
                result_future = asyncio.get_event_loop().create_future()
                self._sync_request_result[sync_height] = result_future

            block, max_block_height, current_unconfirmed_block_height, confirm_info, response_code = (
                await result_future
            )
            del self._sync_request_result[sync_height]

            if (not self._request_limit_event.is_set() and
                    (len(self._sync_request_result) / conf.SYNC_REQUEST_RESULT_MAX_SIZE) <= 0.8):
                self._request_limit_event.set()
                util.logger.debug(f"request limit event set() at {len(self._sync_request_result)}")

            if response_code == message_code.Response.success:
                util.logger.debug(f"try add block height: {block.header.height}")

                max_block_height = max(max_block_height, current_unconfirmed_block_height)
                if max_block_height > max_height:
                    util.logger.debug(f"set max_height: {max_height} -> {max_block_height}")
                    max_height = max_block_height
                    if current_unconfirmed_block_height == max_block_height:
                        unconfirmed_block_height = current_unconfirmed_block_height

                util.logger.debug(
                    f"max_height: {max_height}, "
                    f"max_block_height: {max_block_height}, "
                    f"unconfirmed_block_height: {current_unconfirmed_block_height}, "
                    f"confirm_info: {len(confirm_info)}"
                )
                try:
                    if (max_height == unconfirmed_block_height == block.header.height and
                            max_height > 0 and not confirm_info):
                        self.candidate_blocks.add_block(
                            block, self.blockchain.find_preps_addresses_by_header(block.header))
                        self.blockchain.last_unconfirmed_block = block
                    else:
                        await self._add_block_by_sync(block, confirm_info)

                    if block.header.height == 0:
                        self.__rebuild_nid(block)
                    elif self.blockchain.find_nid() is None:
                        genesis_block = self.blockchain.find_block_by_height(0)
                        self.__rebuild_nid(genesis_block)
                except KeyError as e:
                    util.logger.exception(f"during block height sync: {e!r}")
                    raise
                except exception.BlockError:
                    util.exit_and_msg("Block Error Clear all block and restart peer.")
                    raise
                except Exception as e:
                    util.logger.warning(f"fail block height sync: {e!r}")

                    if self.blockchain.last_block.header.hash != block.header.prev_hash:
                        raise exception.PreviousBlockMismatch
                    else:
                        if sync_height in self._sync_peer_target:
                            peer_target = self._sync_peer_target[sync_height]
                            self.__block_height_sync_bad_targets[peer_target] = max_block_height
                        raise
                else:
                    if sync_height in self._sync_peer_target:
                        del self._sync_peer_target[sync_height]
                    my_height = sync_height
            else:
                if len(peer_stubs) == 1:
                    raise ConnectionError

        return (self.blockchain.block_height,
                unconfirmed_block_height,
                max_height)

    def _block_request_to_peers_in_sync(
            self,
            peer_stubs: List[Tuple],
            my_height: int,
            unconfirmed_block_height: int,
            max_height: int
    ):
        """Extracted func from __block_height_sync.
        It has block request loop with peer_stubs for block height sync.

        :param peer_stubs:
        :param my_height:
        :param unconfirmed_block_height:
        :param max_height:
        """

        util.logger.debug(f"sync start: my_height({my_height}), max_height({max_height})")

        if self.__channel_service.is_support_node_function(conf.NodeFunction.Vote):
            block_request_coroutine = self._block_request(peer_stubs, my_height, max_height)
        else:
            block_request_coroutine = self._citizen_request(my_height, max_height)

        async def synchronizer():
            self._request_limit_event = asyncio.Event(loop=asyncio.get_event_loop())
            self._request_limit_event.set()

            coroutines = [
                block_request_coroutine,
                self._block_sync(peer_stubs, my_height, unconfirmed_block_height, max_height)
            ]

            _, _sync_result = await asyncio.gather(*coroutines)
            return _sync_result

        my_height, unconfirmed_block_height, max_height = asyncio.run(synchronizer())
        util.logger.debug(f"sync finished: current_height({my_height}), "
                          f"unconfirmed block height({unconfirmed_block_height}), "
                          f"max_height({max_height})")

    def request_rollback(self) -> bool:
        """Request block data rollback behind to 1 block

        :return: if rollback success return True, else return False
        """
        target_block = self.blockchain.find_block_by_hash32(self.blockchain.last_block.header.prev_hash)
        if not self.blockchain.check_rollback_possible(target_block):
            util.logger.warning(f"The request cannot be rollback to the target block({target_block}).")
            return False

        request_origin = {
            'blockHeight': target_block.header.height,
            'blockHash': target_block.header.hash.hex_0x()
        }

        request = convert_params(request_origin, ParamType.roll_back)
        stub = StubCollection().icon_score_stubs[ChannelProperty().name]

        util.logger.debug(f"Rollback request({request})")
        response: dict = cast(dict, stub.sync_task().rollback(request))
        try:
            response_to_json_query(response)
        except GenericJsonRpcServerError as e:
            util.logger.warning(f"response error = {e}")
        else:
            result_height = response.get("blockHeight")
            if hex(target_block.header.height) == result_height:
                util.logger.info(f"Rollback Success. result height = {result_height}")
                self.blockchain.rollback(target_block)
                self.rebuild_block()
                return True

        util.logger.warning(f"Rollback Fail. response = {response}")
        return False

    def _block_height_sync(self):
        # Make Peer Stub List [peer_stub, ...] and get max_height of network
        try:
            max_height, unconfirmed_block_height, peer_stubs = self._get_peer_stub_list()

            if self.blockchain.last_unconfirmed_block is not None:
                self.candidate_blocks.remove_block(self.blockchain.last_unconfirmed_block.header.hash)
            self.blockchain.last_unconfirmed_block = None

            my_height = self.blockchain.block_height
            util.logger.debug(f"my_height({my_height}), max_height({max_height})")

            # prevent_next_block_mismatch until last_block_height in block DB.
            # (excludes last_unconfirmed_block_height)
            self.blockchain.prevent_next_block_mismatch(self.blockchain.block_height + 1)
            self._block_request_to_peers_in_sync(peer_stubs,
                                                 my_height,
                                                 unconfirmed_block_height,
                                                 max_height)
        except exception.PreviousBlockMismatch as e:
            util.logger.warning(f"There is a previous block hash mismatch! : {e!r}")
            self.request_rollback()
            self.__start_block_height_sync_timer(is_run_at_start=True)
        except Exception as e:
            util.logger.warning(f"exception during block_height_sync : {e!r}", exc_info=True)
            self.__start_block_height_sync_timer()
        else:
            util.logger.debug(f"block_height_sync is complete.")
            self.__channel_service.state_machine.complete_sync()

    def get_next_leader(self) -> Optional[str]:
        """get next leader from last_block of BlockChain. for new_epoch and set_peer_type_in_channel

        :return:
        """

        block = self.blockchain.last_block

        if block.header.prep_changed_reason is NextRepsChangeReason.TermEnd:
            next_leader = self.blockchain.get_first_leader_of_next_reps(block)
        elif self.blockchain.made_block_count_reached_max(block):
            reps_hash = block.header.revealed_next_reps_hash or ChannelProperty().crep_root_hash
            reps = self.blockchain.find_preps_addresses_by_roothash(reps_hash)
            next_leader = self.blockchain.get_next_rep_string_in_reps(block.header.peer_id, reps)

            if next_leader is None:
                next_leader = self.__get_next_leader_by_block(block)
        else:
            next_leader = self.__get_next_leader_by_block(block)

        util.logger.debug(f"next_leader({next_leader}) from block({block.header.height})")
        return next_leader

    def __get_next_leader_by_block(self, block: Block) -> str:
        if block.header.next_leader is None:
            if block.header.peer_id:
                return block.header.peer_id.hex_hx()
            else:
                return ExternalAddress.empty().hex_hx()
        else:
            return block.header.next_leader.hex_hx()

    def _get_peer_stub_list(self) -> Tuple[int, int, List[Tuple[str, Any]]]:
        """It updates peer list for block manager refer to peer list on the loopchain network.
        This peer list is not same to the peer list of the loopchain network.

        :return max_height: a height of current blockchain
        :return unconfirmed_block_height: unconfirmed_block_height on the network
        :return peer_stubs: current peer list on the network (target, peer_stub)
        """
        max_height = -1      # current max height
        unconfirmed_block_height = -1
        peer_stubs = []     # peer stub list for block height synchronization

        rs_client: RestClient = self.__channel_service.rs_client

        if not self.__channel_service.is_support_node_function(conf.NodeFunction.Vote):
            status_response = rs_client.call(RestMethod.Status)
            max_height = status_response['block_height']
            peer_stubs.append((rs_client.target, rs_client))
            return max_height, unconfirmed_block_height, peer_stubs

        # Make Peer Stub List [peer_stub, ...] and get max_height of network
        self.__block_height_sync_bad_targets = {k: v for k, v in self.__block_height_sync_bad_targets.items()
                                                if v > self.blockchain.block_height}
        util.logger.info(f"Bad Block Sync Peer : {self.__block_height_sync_bad_targets}")
        peer_target = ChannelProperty().peer_target
        my_height = self.blockchain.block_height

        port_pattern = re.compile(r":([0-9]{2,5})$")

        def _converter(target) -> str:
            port = int(port_pattern.search(target).group(1))
            new_port = f":{port + conf.PORT_DIFF_REST_SERVICE_CONTAINER}"
            return port_pattern.sub(new_port, target)

        endpoints = {target: _converter(target) for target in self.get_target_list()}

        for grpc_endpoint, rest_endpoint in endpoints.items():
            if grpc_endpoint == peer_target:
                continue
            if grpc_endpoint in self.__block_height_sync_bad_targets:
                continue
            util.logger.debug(f"try to grpc_endpoint({grpc_endpoint}), rest_endpoint({rest_endpoint})")
            channel = GRPCHelper().create_client_channel(grpc_endpoint)
            stub = loopchain_pb2_grpc.PeerServiceStub(channel)
            try:
                client = RestClient(self.channel_name, rest_endpoint)
                response: dict = client.call(RestMethod.Status, timeout=conf.REST_TIMEOUT)
                target_block_height = max(response["block_height"], response["unconfirmed_block_height"])

                recovery = response.get("recovery", {})
                # only recovery_mode node should be included in block sync when running by recovery_mode
                if conf.RECOVERY_MODE and not recovery.get("mode", False):
                    continue

                if target_block_height > my_height:
                    peer_stubs.append((grpc_endpoint, stub))
                    max_height = max(max_height, target_block_height)
                    unconfirmed_block_height = max(unconfirmed_block_height, response["unconfirmed_block_height"])

            except Exception as e:
                util.logger.warning(f"This peer has already been removed from the block height target node. {e!r}")

        return max_height, unconfirmed_block_height, peer_stubs

    def get_target_list(self) -> List[str]:
        if self.blockchain.last_block:
            reps_hash = self.blockchain.get_reps_hash_by_header(self.blockchain.last_block.header)
        else:
            reps_hash = ChannelProperty().crep_root_hash
        rep_targets = self.blockchain.find_preps_targets_by_roothash(reps_hash)
        return list(rep_targets.values())

    def new_epoch(self):
        new_leader_id = self.get_next_leader()
        self.epoch = Epoch(self, new_leader_id)
        util.logger.info(f"Epoch height({self.epoch.height}), leader({self.epoch.leader_id})")

    def stop(self):
        self.__block_height_thread_pool.shutdown()

        if self.consensus_algorithm:
            self.consensus_algorithm.stop()

        # close store(aka. leveldb) after cleanup all threads
        # because hard crashes may occur.
        # https://plyvel.readthedocs.io/en/latest/api.html#DB.close
        self.blockchain.close_blockchain_store()

    def add_complain(self, vote: LeaderVote):
        util.logger.spam(f"vote({vote})")

        if not self.epoch:
            util.logger.debug(f"Epoch is not initialized.")
            return

        if self.epoch.height == vote.block_height:
            if self.epoch.round == vote.round:
                self.epoch.add_complain(vote)
                elected_leader = self.epoch.complain_result()
                if elected_leader:
                    self.__channel_service.reset_leader(elected_leader, complained=True)
            elif self.epoch.round > vote.round:
                if vote.new_leader != ExternalAddress.empty():
                    self.__send_fail_leader_vote(vote)
                else:
                    return
            else:
                # TODO: do round sync
                return
        elif self.epoch.height < vote.block_height:
            self.__channel_service.state_machine.block_sync()

    def __send_fail_leader_vote(self, leader_vote: LeaderVote):
        version = self.blockchain.block_versioner.get_version(leader_vote.block_height)
        fail_vote = Vote.get_leader_vote_class(version).new(
            signer=ChannelProperty().peer_auth,
            block_height=leader_vote.block_height,
            round_=leader_vote.round,
            old_leader=leader_vote.old_leader,
            new_leader=ExternalAddress.empty(),
            timestamp=util.get_time_stamp()
        )

        fail_vote_dumped = json.dumps(fail_vote.serialize())
        request = loopchain_pb2.ComplainLeaderRequest(
            complain_vote=fail_vote_dumped,
            channel=self.channel_name
        )

        reps_hash = self.blockchain.last_block.header.revealed_next_reps_hash or ChannelProperty().crep_root_hash
        rep_id = leader_vote.rep.hex_hx()
        target = self.blockchain.find_preps_targets_by_roothash(reps_hash)[rep_id]

        util.logger.debug(
            f"fail leader complain "
            f"complained_leader_id({leader_vote.old_leader}), "
            f"new_leader_id({ExternalAddress.empty()}),"
            f"round({leader_vote.round}),"
            f"target({target})")

        self.__channel_service.broadcast_scheduler.schedule_send_failed_leader_complain(
            "ComplainLeader", request, target=target
        )

    def get_leader_ids_for_complaint(self) -> Tuple[str, str]:
        """
        :return: Return complained_leader_id and new_leader_id for the Leader Complaint.
        """
        complained_leader_id = self.epoch.leader_id

        new_leader = self.blockchain.get_next_rep_in_reps(
            ExternalAddress.fromhex(complained_leader_id), self.epoch.reps)
        new_leader_id = new_leader.hex_hx() if new_leader else None

        if not isinstance(new_leader_id, str):
            new_leader_id = ""

        if not isinstance(complained_leader_id, str):
            complained_leader_id = ""

        return complained_leader_id, new_leader_id

    def leader_complain(self):
        complained_leader_id, new_leader_id = self.get_leader_ids_for_complaint()
        version = self.blockchain.block_versioner.get_version(self.epoch.height)
        leader_vote = Vote.get_leader_vote_class(version).new(
            signer=ChannelProperty().peer_auth,
            block_height=self.epoch.height,
            round_=self.epoch.round,
            old_leader=ExternalAddress.fromhex_address(complained_leader_id),
            new_leader=ExternalAddress.fromhex_address(new_leader_id),
            timestamp=util.get_time_stamp()
        )
        util.logger.info(
            f"LeaderVote : old_leader({complained_leader_id}), new_leader({new_leader_id}), round({self.epoch.round})")
        self.add_complain(leader_vote)

        leader_vote_serialized = leader_vote.serialize()
        leader_vote_dumped = json.dumps(leader_vote_serialized)
        request = loopchain_pb2.ComplainLeaderRequest(
            complain_vote=leader_vote_dumped,
            channel=self.channel_name
        )

        util.logger.debug(
            f"complained_leader_id({complained_leader_id}), "
            f"new_leader_id({new_leader_id})")

        reps_hash = self.blockchain.get_next_reps_hash_by_header(self.blockchain.last_block.header)
        self.__channel_service.broadcast_scheduler.schedule_broadcast("ComplainLeader",
                                                                      request,
                                                                      reps_hash=reps_hash)

    def vote_unconfirmed_block(self, block: Block, round_: int, is_validated):
        util.logger.debug(f"height({block.header.height}), "
                          f"block_hash({block.header.hash}), "
                          f"is_validated({is_validated})")
        vote = Vote.get_block_vote_class(block.header.version).new(
            signer=ChannelProperty().peer_auth,
            block_height=block.header.height,
            round_=round_,
            block_hash=block.header.hash if is_validated else Hash32.empty(),
            timestamp=util.get_time_stamp()
        )
        self.candidate_blocks.add_vote(vote)

        vote_serialized = vote.serialize()
        vote_dumped = json.dumps(vote_serialized)
        block_vote = loopchain_pb2.BlockVote(vote=vote_dumped, channel=ChannelProperty().name)

        target_reps_hash = block.header.reps_hash or ChannelProperty().crep_root_hash

        self.__channel_service.broadcast_scheduler.schedule_broadcast(
            "VoteUnconfirmedBlock",
            block_vote,
            reps_hash=target_reps_hash
        )

        return vote

    def verify_confirm_info(self, unconfirmed_block: Block):
        unconfirmed_header = unconfirmed_block.header
        my_height = self.blockchain.block_height
        util.logger.info(f"my_height({my_height}), unconfirmed_block_height({unconfirmed_header.height})")

        if my_height < (unconfirmed_header.height - 2):
            raise ConfirmInfoInvalidNeedBlockSync(
                f"trigger block sync: my_height({my_height}), "
                f"unconfirmed_block.header.height({unconfirmed_header.height})"
            )

        is_rep = ObjectManager().channel_service.is_support_node_function(conf.NodeFunction.Vote)
        if is_rep and my_height == unconfirmed_header.height - 2 and not self.blockchain.last_unconfirmed_block:
            raise ConfirmInfoInvalidNeedBlockSync(
                f"trigger block sync: my_height({my_height}), "
                f"unconfirmed_block.header.height({unconfirmed_header.height}), "
                f"last_unconfirmed_block({self.blockchain.last_unconfirmed_block})"
            )

        # a block is already added that same height unconfirmed_block height
        if my_height >= unconfirmed_header.height:
            raise ConfirmInfoInvalidAddedBlock(
                f"block is already added my_height({my_height}), "
                f"unconfirmed_block.header.height({unconfirmed_header.height})")

        block_verifier = BlockVerifier.new(unconfirmed_header.version, self.blockchain.tx_versioner)
        prev_block = self.blockchain.get_prev_block(unconfirmed_block)
        reps_getter = self.blockchain.find_preps_addresses_by_roothash

        util.logger.spam(f"prev_block: {prev_block.header.hash if prev_block else None}")
        if not prev_block:
            raise NotReadyToConfirmInfo(
                "There is no prev block or not ready to confirm block (Maybe node is starting)")

        try:
            if prev_block and prev_block.header.reps_hash and unconfirmed_header.height > 1:
                prev_reps = reps_getter(prev_block.header.reps_hash)
                block_verifier.verify_prev_votes(unconfirmed_block, prev_reps)
        except Exception as e:
            util.logger.warning(f"{e!r}")
            traceback.print_exc()
            raise ConfirmInfoInvalid("Unconfirmed block has no valid confirm info for previous block")

    def _vote(self, unconfirmed_block: Block, round_: int):
        exc = None
        try:
            block_version = self.blockchain.block_versioner.get_version(unconfirmed_block.header.height)
            block_verifier = BlockVerifier.new(block_version, self.blockchain.tx_versioner)
            block_verifier.invoke_func = self.blockchain.score_invoke
            reps_getter = self.blockchain.find_preps_addresses_by_roothash

            util.logger.debug(f"unconfirmed_block.header({unconfirmed_block.header})")

            block_verifier.verify(unconfirmed_block,
                                  self.blockchain.last_block,
                                  self.blockchain,
                                  generator=self.blockchain.get_expected_generator(unconfirmed_block),
                                  reps_getter=reps_getter)
        except NotInReps as e:
            util.logger.debug(f"Not In Reps({e}) state({self.__channel_service.state_machine.state})")
        except BlockHeightMismatch as e:
            exc = e
            util.logger.warning(f"Don't vote to the block of unexpected height. {e!r}")
        except Exception as e:
            exc = e
            util.logger.exception(f"{e!r}")
        else:
            self.candidate_blocks.add_block(
                unconfirmed_block, self.blockchain.find_preps_addresses_by_header(unconfirmed_block.header))
        finally:
            if isinstance(exc, BlockHeightMismatch):
                return

            is_validated = exc is None
            vote = self.vote_unconfirmed_block(unconfirmed_block, round_, is_validated)
            if self.__channel_service.state_machine.state == "BlockGenerate" and self.consensus_algorithm:
                self.consensus_algorithm.vote(vote)

    def vote_as_peer(self, unconfirmed_block: Block, round_: int):
        """Vote to AnnounceUnconfirmedBlock
        """
        util.logger.debug(
            f"height({unconfirmed_block.header.height}) "
            f"round({round_}) "
            f"unconfirmed_block({unconfirmed_block.header.hash.hex()})")
        util.logger.warning(f"last_block({self.blockchain.last_block.header.hash})")

        try:
            self.add_unconfirmed_block(unconfirmed_block, round_)
        except InvalidUnconfirmedBlock as e:
            self.candidate_blocks.remove_block(unconfirmed_block.header.hash)
            util.logger.warning(f"{e!r}")
        except RoundMismatch as e:
            self.candidate_blocks.remove_block(unconfirmed_block.header.prev_hash)
            util.logger.warning(f"{e!r}")
        except UnrecordedBlock as e:
            util.logger.info(f"{e!r}")
        except DuplicationUnconfirmedBlock as e:
            util.logger.debug(f"{e!r}")
            self._vote(unconfirmed_block, round_)
        else:
            self._vote(unconfirmed_block, round_)
