"""Block Height Sync
"""

import asyncio
import json
import re
import threading
import traceback
from collections import OrderedDict
from concurrent.futures import Future
from concurrent.futures.thread import ThreadPoolExecutor
from typing import TYPE_CHECKING, List, Tuple, Dict, Optional, Union, Coroutine, Set, Any

from pkg_resources import parse_version

from loopchain import utils, configure as conf
from loopchain.baseservice.rest_client import RestClient, RestMethod
from loopchain.blockchain import exception
from loopchain.blockchain.blocks import Block, BlockVerifier, BlockSerializer
from loopchain.blockchain.votes import Votes
from loopchain.channel.channel_property import ChannelProperty
from loopchain.protos import loopchain_pb2, loopchain_pb2_grpc, message_code
from loopchain.tools.grpc_helper import GRPCHelper

if TYPE_CHECKING:
    from loopchain.peer.block_manager import BlockManager
    from loopchain.channel.channel_service import ChannelService

RequestResult = Tuple[Block, int, int, Union[List, bytes], int]


class BlockSync:
    """Block Sync
    """

    def __init__(self, block_manager: 'BlockManager', channel_service: 'ChannelService'):
        self._block_manager = block_manager
        self._channel_service = channel_service

        self._blockchain = block_manager.blockchain

        self._block_height_sync_bad_targets = {}
        self._block_height_sync_lock = threading.Lock()
        self._block_height_thread_pool: ThreadPoolExecutor = ThreadPoolExecutor(1, 'BlockHeightSyncThread')
        self._block_height_future: Optional[Future] = None

        self._max_height = 0
        self._sync_peer_index = 0
        self._sync_request_result: Dict[int, asyncio.Future] = dict()
        self._sync_peer_target: Dict[int, str] = dict()
        self._request_limit_event: Optional[asyncio.Event] = None
        self._sync_done_event: Optional[asyncio.Event] = None

    def block_height_sync(self):
        def _print_exception(fut):
            exc = fut.exception()
            if exc:
                traceback.print_exception(type(exc), exc, exc.__traceback__)

        with self._block_height_sync_lock:
            need_to_sync = (self._block_height_future is None or self._block_height_future.done())

            if need_to_sync:
                self._channel_service.stop_leader_complain_timer()
                self._block_height_future = self._block_height_thread_pool.submit(self._block_height_sync)
                self._block_height_future.add_done_callback(_print_exception)
            else:
                utils.logger.warning('Tried block_height_sync. But failed. The thread is already running')

    def _init_unconfirmed_block(self):
        if self._blockchain.last_unconfirmed_block is not None:
            self._block_manager.candidate_blocks.remove_block(self._blockchain.last_unconfirmed_block.header.hash)
            self._blockchain.last_unconfirmed_block = None

    def _block_height_sync(self):
        # Make Peer Stub List [peer_stub, ...] and get max_height of network
        try:
            self._max_height, unconfirmed_block_height, peer_stubs = self._get_peer_stub_list()

            self._init_unconfirmed_block()

            my_height = self._blockchain.block_height
            utils.logger.debug(f"start sync. my_height({my_height}), max_height({self._max_height})")

            # prevent_next_block_mismatch until last_block_height in block DB.
            # (excludes last_unconfirmed_block_height)
            self._blockchain.prevent_next_block_mismatch(self._blockchain.block_height + 1)
            self._block_request_to_peers_in_sync(peer_stubs,
                                                 my_height,
                                                 unconfirmed_block_height)
        except exception.PreviousBlockMismatch as e:
            utils.logger.warning(f"There is a previous block hash mismatch! : {e!r}")
            self._block_manager.request_rollback()
            self._block_manager.start_block_height_sync_timer(is_run_at_start=True)
        except Exception as e:
            utils.logger.warning(f"exception during block_height_sync : {e!r}", exc_info=True)
            self._block_manager.start_block_height_sync_timer()
        else:
            utils.logger.debug(f"block_height_sync is complete.")
            self._channel_service.state_machine.complete_sync()

    def _block_request_to_peers_in_sync(
            self,
            peer_stubs: List[Tuple],
            my_height: int,
            unconfirmed_block_height: int
    ):
        """Extracted func from __block_height_sync.
        It has block request loop with peer_stubs for block height sync.

        :param peer_stubs:
        :param my_height:
        :param unconfirmed_block_height:
        """

        utils.logger.debug(f"start sync. my_height({my_height}), max_height({self._max_height})")

        if self._channel_service.is_support_node_function(conf.NodeFunction.Vote):
            block_request_coroutine = self._block_request(peer_stubs, my_height)
        else:
            block_request_coroutine = self._citizen_request(my_height)

        async def synchronizer():
            self._request_limit_event = asyncio.Event(loop=asyncio.get_event_loop())
            self._request_limit_event.set()

            coroutines = [
                block_request_coroutine,
                self._block_sync(peer_stubs, my_height, unconfirmed_block_height)
            ]

            _, _sync_result = await asyncio.gather(*coroutines)
            return _sync_result

        try:
            my_height, unconfirmed_block_height, max_height = asyncio.run(synchronizer())
            utils.logger.debug(f"sync finished: current_height({my_height}), "
                               f"unconfirmed block height({unconfirmed_block_height}), "
                               f"max_height({max_height})")
        finally:
            self._cleanup()

    async def _block_request(self, peer_stubs: List[Tuple], block_height: int):
        """request block by gRPC

        :param peer_stubs:
        :param block_height:
        :return
        """
        self._sync_done_event = asyncio.Event(loop=asyncio.get_event_loop())

        origin_block_height = block_height
        max_height_block_is_unconfirmed_block = False

        while self._max_height > block_height:
            request_height = block_height + 1
            self._sync_peer_target[request_height], peer_stub = peer_stubs[self._sync_peer_index]
            utils.logger.debug(f"request height: {request_height}, "
                               f"request target: {self._sync_peer_target[request_height]}")
            try:
                result_future = self._sync_request_result.get(request_height, None)
                if result_future is None:
                    result_future = asyncio.get_event_loop().create_future()
                    self._sync_request_result[request_height] = result_future

                # FIXME : block_request to asyncio_loop.run_in_executor
                request_result = self._block_request_by_voter(request_height, peer_stub)
                result_future.set_result(request_result)

                _, _max_height, _unconfirmed_block_height, _, response_code = request_result
                max_block_height = max(_max_height, _unconfirmed_block_height)
                if self._max_height < max_block_height:
                    self._max_height = max_block_height
                    utils.logger.debug(f"new max_height : {self._max_height}")

                if request_height == self._max_height == _unconfirmed_block_height:
                    max_height_block_is_unconfirmed_block = True

            except exception.NoConfirmInfo as e:
                utils.logger.warning(f"{e!r}")
                response_code = message_code.Response.fail_no_confirm_info
            except Exception as e:
                utils.logger.exception(f"There is a bad peer: {e!r}")
                response_code = message_code.Response.fail

            if response_code == message_code.Response.success:
                if (len(peer_stubs) > 1 and
                        (request_height - origin_block_height) % conf.SYNC_BLOCK_COUNT_PER_NODE == 0):
                    self._sync_peer_index = (self._sync_peer_index + 1) % len(peer_stubs)

                if len(self._sync_request_result) >= conf.SYNC_REQUEST_RESULT_MAX_SIZE:
                    utils.logger.debug(f"waiting event on sync request size: {len(self._sync_request_result)}")
                    self._request_limit_event.clear()
                    await self._request_limit_event.wait()
                else:
                    await asyncio.sleep(0)

                block_height = request_height
            else:
                if len(peer_stubs) == 1:
                    raise ConnectionError

                self._sync_peer_index = (self._sync_peer_index + 1) % len(peer_stubs)

            if self._max_height <= block_height and len(self._sync_request_result) > 0:
                utils.logger.debug(f"waiting on sync done: max_height = {self._max_height}")
                await self._sync_done_event.wait()
                if self._max_height <= block_height:
                    break

                utils.logger.debug(f"new max height({self._max_height}), "
                                   f"request_height({request_height}) "
                                   f"is unconfirmed block({max_height_block_is_unconfirmed_block})")
                if max_height_block_is_unconfirmed_block:
                    block_height = request_height - 1

        utils.logger.info(f"finished. max_height({self._max_height})")

    def _block_request_by_voter(self, block_height, peer_stub) -> RequestResult:
        response = peer_stub.BlockSync(loopchain_pb2.BlockSyncRequest(
            block_height=block_height,
            channel=self._block_manager.channel_name
        ), conf.GRPC_TIMEOUT)

        if response.response_code == message_code.Response.fail_no_confirm_info:
            raise exception.NoConfirmInfo(f"The peer has not confirm_info of the block by height({block_height}).")
        elif response.response_code in (message_code.Response.fail_not_enough_data,
                                        message_code.Response.fail_wrong_block_height):
            raise exception.BlockError(f"Received block is invalid: "
                                       f"response_message={message_code.get_response_msg(response.response_code)}")
        else:
            try:
                block = self._blockchain.block_loads(response.block)
            except Exception as e:
                traceback.print_exc()
                raise exception.BlockError(f"Received block is invalid: original exception={e}") from e

            votes_dumped: bytes = response.confirm_info
            try:
                votes_serialized = json.loads(votes_dumped)
                version = self._blockchain.block_versioner.get_version(block_height)
                votes = Votes.get_block_votes_class(version).deserialize_votes(votes_serialized)
            except json.JSONDecodeError:
                votes = votes_dumped

        return block, response.max_block_height, response.unconfirmed_block_height, votes, response.response_code

    async def _block_request_by_citizen(self, block_height: int) -> RequestResult:
        max_height = self._max_height
        rs_client = self._channel_service.rs_client
        get_block_result = await rs_client.call_async(
            RestMethod.GetBlockByHeight,
            RestMethod.GetBlockByHeight.value.params(height=str(block_height))
        )

        response_code = get_block_result["response_code"]
        if response_code != message_code.Response.success:
            raise exception.MessageCodeError(f"getBlockByHeight failed {message_code.get_response(response_code)}")

        if max_height == block_height:
            last_block_height = self._get_last_block_height(rs_client)
            if last_block_height > max_height:
                max_height = last_block_height

        block_version = self._blockchain.block_versioner.get_version(block_height)
        block_serializer = BlockSerializer.new(block_version, self._blockchain.tx_versioner)
        block = block_serializer.deserialize(get_block_result['block'])
        votes_dumped: str = get_block_result.get('confirm_info', '')
        try:
            votes_serialized = json.loads(votes_dumped)
            version = self._blockchain.block_versioner.get_version(block_height)
            votes = Votes.get_block_votes_class(version).deserialize_votes(votes_serialized)
        except json.JSONDecodeError:
            votes = votes_dumped
        return block, max_height, -1, votes, message_code.Response.success

    def _get_last_block_height(self, rs_client) -> int:
        retry_count = 0

        max_height = -1
        while retry_count < conf.CITIZEN_ASYNC_REQUEST_RETRY_TIMES:
            last_block = rs_client.call(RestMethod.GetLastBlock)
            if not last_block:
                utils.logging.warning("The Radiostation may not be ready. It will retry after a while.")
                retry_count += 1
            else:
                max_height = self._blockchain.block_versioner.get_height(last_block)
                break

        return max_height

    async def _citizen_request(self, block_height: int):
        request_coros: OrderedDict[int, Coroutine[int, int, RequestResult]] = OrderedDict()
        request_successes: Set[int] = set()
        request_height = block_height

        while True:
            if self._max_height > request_height:
                request_height += 1
                request_coros[request_height] = self._block_request_by_citizen(request_height)

            if self._max_height <= request_height or len(request_coros) == conf.CITIZEN_REQUEST_SIZE_CONCURRENTLY:
                utils.logger.debug(f"request heights: {request_coros.keys()}, size: {len(request_coros)}")
                for done_future in asyncio.as_completed(request_coros.values()):
                    try:
                        request_result: RequestResult = await done_future
                    except Exception as e:
                        utils.logging.exception(f"sync request failed caused by {e!r}")
                    else:
                        _block, _max_height, _unconfirmed_block_height, _, response_code = request_result
                        utils.logger.debug(f"block_height({_block.header.height}) received")

                        result_future: asyncio.Future = self._sync_request_result.get(_block.header.height, None)
                        if result_future is None:
                            result_future = asyncio.get_event_loop().create_future()
                            self._sync_request_result[_block.header.height] = result_future
                        result_future.set_result(request_result)

                        max_block_height = max(_max_height, _unconfirmed_block_height)
                        if self._max_height < max_block_height:
                            self._max_height = max_block_height
                            utils.logger.debug(f"new max_height : {self._max_height}")

                        request_successes.add(_block.header.height)

                request_failed = set(request_coros.keys()) - request_successes
                if request_failed:
                    utils.logger.warning(f"These heights({request_failed}) can't get Block Information.")

                request_coros.clear()

                # retry request at failed heights
                for retry_height in request_failed:
                    request_coros[retry_height] = self._block_request_by_citizen(retry_height)

                if len(self._sync_request_result) >= conf.SYNC_REQUEST_RESULT_MAX_SIZE:
                    utils.logger.debug(f"waiting on sync request size: {len(self._sync_request_result)}")
                    self._request_limit_event.clear()
                    await self._request_limit_event.wait()

            if request_height >= self._max_height and not request_coros:
                break

        utils.logger.info(f"finished. max_height({self._max_height})")

    async def _block_sync(
            self,
            peer_stubs: List[Tuple],
            my_height: int,
            unconfirmed_block_height: int
    ) -> Tuple[int, int, int]:
        """It has block request loop with peer_stubs for block height sync.

        :param peer_stubs: list of (endpoint, peer_stub)
        :param my_height:
        :param unconfirmed_block_height:
        :return: last_block_height, unconfirmed_block_height, max_height
        """
        asyncio.get_event_loop().set_default_executor(ThreadPoolExecutor(1))

        while self._max_height > my_height:
            if self._channel_service.state_machine.state != 'BlockSync':
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
                    (len(self._sync_request_result) / conf.SYNC_REQUEST_RESULT_MAX_SIZE) <= 0.5):
                self._request_limit_event.set()
                utils.logger.debug(f"request limit event set() at {len(self._sync_request_result)}")

            if response_code == message_code.Response.success:
                utils.logger.debug(f"try add block height: {block.header.height}")

                max_block_height = max(max_block_height, current_unconfirmed_block_height)
                if self._max_height <= max_block_height == current_unconfirmed_block_height:
                    unconfirmed_block_height = current_unconfirmed_block_height

                utils.logger.debug(
                    f"max_height: {self._max_height}, "
                    f"max_block_height: {max_block_height}, "
                    f"unconfirmed_block_height: {current_unconfirmed_block_height}, "
                    f"confirm_info count: {len(confirm_info)}"
                )
                try:
                    if (self._max_height == unconfirmed_block_height == block.header.height and
                            self._max_height > 0 and not confirm_info):

                        if self._update_max_height(peer_stubs, sync_height):
                            continue
                        else:
                            self._block_manager.candidate_blocks.add_block(
                                block, self._blockchain.find_preps_addresses_by_header(block.header))
                            self._blockchain.last_unconfirmed_block = block
                    else:
                        await asyncio.get_event_loop().run_in_executor(
                            None,
                            self._add_block_by_sync,
                            block,
                            confirm_info
                        )

                    if block.header.height == 0:
                        self._block_manager.rebuild_nid(block)
                    elif self._blockchain.find_nid() is None:
                        genesis_block = self._blockchain.find_block_by_height(0)
                        self._block_manager.rebuild_nid(genesis_block)
                except KeyError as e:
                    utils.logger.exception(f"during block height sync: {e!r}")
                    raise
                except exception.BlockError:
                    utils.exit_and_msg("Block Error Clear all block and restart peer.")
                    raise
                except Exception as e:
                    utils.logger.warning(f"fail block height sync: {e!r}")

                    if self._blockchain.last_block.header.hash != block.header.prev_hash:
                        raise exception.PreviousBlockMismatch
                    else:
                        if sync_height in self._sync_peer_target:
                            peer_target = self._sync_peer_target[sync_height]
                            self._block_height_sync_bad_targets[peer_target] = max_block_height
                        raise
                else:
                    if sync_height in self._sync_peer_target:
                        del self._sync_peer_target[sync_height]
                    my_height = sync_height
            else:
                if len(peer_stubs) == 1:
                    raise ConnectionError

            if self._update_max_height(peer_stubs, sync_height):
                self._init_unconfirmed_block()

        return (self._blockchain.block_height,
                unconfirmed_block_height,
                self._max_height)

    def _update_max_height(self, peer_stubs: List[Tuple], sync_height: int) -> bool:
        """Update max height if max height changed
        :param peer_stubs:
        :param sync_height:
        :return: True if max height changed else False
        """
        result = False
        if (self._sync_done_event is not None
                and not self._sync_done_event.is_set()
                and self._max_height <= sync_height):
            try:
                _, peer_stub = peer_stubs[self._sync_peer_index]

                response = peer_stub.BlockSync(loopchain_pb2.BlockSyncRequest(
                    block_height=sync_height,
                    channel=self._block_manager.channel_name
                ), conf.GRPC_TIMEOUT)

                new_max_height = max(response.max_block_height, response.unconfirmed_block_height)
                if self._max_height < new_max_height:
                    result = True
                    self._max_height = new_max_height
                    utils.logger.debug(f"set new max height: {self._max_height}")
            finally:
                self._sync_done_event.set()

        return result

    def _add_block_by_sync(self, block_, confirm_info: Optional[List] = None):
        """
        TODO : If possible, change _add_block_by_sync to coroutine

        :param block_:
        :param confirm_info:
        :return:
        """
        utils.logger.debug(f"height({block_.header.height}) hash({block_.header.hash})")

        block_version = self._blockchain.block_versioner.get_version(block_.header.height)
        block_verifier = BlockVerifier.new(block_version, self._blockchain.tx_versioner, raise_exceptions=False)
        block_verifier.invoke_func = self._blockchain.get_invoke_func(block_.header.height)

        reps_getter = self._blockchain.find_preps_addresses_by_roothash
        block_verifier.verify_loosely(block_,
                                      self._blockchain.last_block,
                                      self._blockchain,
                                      reps_getter=reps_getter)

        need_to_write_tx_info, need_to_score_invoke = True, True
        for exc in block_verifier.exceptions:
            if isinstance(exc, exception.TransactionDuplicatedHashError):
                need_to_write_tx_info = False
            if isinstance(exc, exception.ScoreInvokeError) and not need_to_write_tx_info:
                need_to_score_invoke = False

        exc = next((exc for exc in block_verifier.exceptions
                    if not isinstance(exc, exception.TransactionDuplicatedHashError)), None)
        if exc:
            if isinstance(exc, exception.ScoreInvokeError) and not need_to_score_invoke:
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

        self._blockchain.add_block(block_, confirm_info, need_to_write_tx_info, need_to_score_invoke)

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

        rs_client: RestClient = self._channel_service.rs_client

        if not self._channel_service.is_support_node_function(conf.NodeFunction.Vote):
            status_response = rs_client.call(RestMethod.Status)
            max_height = status_response['block_height']
            peer_stubs.append((rs_client.target, rs_client))
            return max_height, unconfirmed_block_height, peer_stubs

        # Make Peer Stub List [peer_stub, ...] and get max_height of network
        self._block_height_sync_bad_targets = {k: v for k, v in self._block_height_sync_bad_targets.items()
                                               if v > self._blockchain.block_height}
        utils.logger.info(f"Bad Block Sync Peer : {self._block_height_sync_bad_targets}")
        peer_target = ChannelProperty().peer_target
        my_height = self._blockchain.block_height

        port_pattern = re.compile(r":([0-9]{2,5})$")

        def _converter(target) -> str:
            port = int(port_pattern.search(target).group(1))
            new_port = f":{port + conf.PORT_DIFF_REST_SERVICE_CONTAINER}"
            return port_pattern.sub(new_port, target)

        endpoints = {target: _converter(target) for target in self._block_manager.get_target_list()}

        for grpc_endpoint, rest_endpoint in endpoints.items():
            if grpc_endpoint == peer_target:
                continue
            if grpc_endpoint in self._block_height_sync_bad_targets:
                continue
            utils.logger.debug(f"try to grpc_endpoint({grpc_endpoint}), rest_endpoint({rest_endpoint})")
            channel = GRPCHelper().create_client_channel(grpc_endpoint)
            stub = loopchain_pb2_grpc.PeerServiceStub(channel)
            try:
                client = RestClient(self._block_manager.channel_name, rest_endpoint)
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
                utils.logger.warning(f"This peer has already been removed from the block height target node. {e!r}")

        return max_height, unconfirmed_block_height, peer_stubs

    def _cleanup(self):
        utils.logger.debug(f"sync_request_result({len(self._sync_request_result)}), "
                           f"sync_peer_target({len(self._sync_peer_target)})")

        self._max_height = 0
        self._sync_peer_index = 0

        for f in self._sync_request_result.values():
            f.cancel()
        self._sync_request_result.clear()
        self._sync_peer_target.clear()
        self._request_limit_event = None
        self._sync_done_event = None

    def stop(self):
        self._cleanup()

        if self._block_height_thread_pool:
            self._block_height_thread_pool.shutdown()
