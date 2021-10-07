"""A management class for blockchain."""

import json
import traceback
from collections import defaultdict
from typing import TYPE_CHECKING, Dict, DefaultDict, Optional, Tuple, List, Union, cast

from pkg_resources import parse_version

import loopchain.utils as util
from loopchain import configure as conf
from loopchain.baseservice import TimerService, ObjectManager, Timer, RestMethod
from loopchain.baseservice.aging_cache import AgingCache
from loopchain.blockchain import (BlockChain, CandidateBlocks, Epoch, BlockchainError, NID, BlockHeightMismatch,
                                  RoundMismatch)
from loopchain.blockchain.blocks import Block, BlockVerifier
from loopchain.blockchain.blocks.block import NextRepsChangeReason
from loopchain.blockchain.exception import (ConfirmInfoInvalid, ConfirmInfoInvalidAddedBlock, NotInReps,
                                            NotReadyToConfirmInfo, UnrecordedBlock, UnexpectedLeader)
from loopchain.blockchain.exception import ConfirmInfoInvalidNeedBlockSync
from loopchain.blockchain.exception import InvalidUnconfirmedBlock, DuplicationUnconfirmedBlock
from loopchain.blockchain.transactions import Transaction, TransactionSerializer, v2, v3
from loopchain.blockchain.types import ExternalAddress
from loopchain.blockchain.types import TransactionStatusInQueue, Hash32
from loopchain.blockchain.votes import Vote, Votes
from loopchain.blockchain.votes.v0_5 import LeaderVote
from loopchain.channel.channel_property import ChannelProperty
from loopchain.jsonrpc import GenericJsonRpcServerError
from loopchain.peer import status_code
from loopchain.peer.block_sync import BlockSync
from loopchain.peer.consensus_siever import ConsensusSiever
from loopchain.protos import loopchain_pb2
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

        self.set_peer_type(loopchain_pb2.PEER)
        self.__service_status = status_code.Service.online

        # old_block_hashes[height][new_block_hash] = old_block_hash
        self.__old_block_hashes: DefaultDict[int, Dict[Hash32, Hash32]] = defaultdict(dict)
        self.epoch: Epoch = None

        self._block_sync = BlockSync(self, channel_service)

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
                send_kwargs["from_recovery"] = True

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
        """Monitors the node's tx_queue status and, if necessary, changes the properties of the sub-service according to the policy.

        :return: count of unconfirmed tx
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
            self.rebuild_nid(genesis_block)
        else:
            ChannelProperty().nid = nid

    def rebuild_nid(self, block: Block):
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

    def start_block_height_sync(self):
        self._block_sync.block_height_sync()

    def start_block_height_sync_timer(self, is_run_at_start=False):
        timer_key = TimerService.TIMER_KEY_BLOCK_HEIGHT_SYNC
        timer_service: TimerService = self.__channel_service.timer_service

        if timer_key not in timer_service.timer_list:
            util.logger.spam(f"add timer for block_request_call to radiostation...")
            timer_service.add_timer(
                timer_key,
                Timer(
                    target=timer_key,
                    duration=conf.GET_LAST_BLOCK_TIMER,
                    callback=self.start_block_height_sync,
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
        self._block_sync.stop()

        if self.consensus_algorithm:
            self.consensus_algorithm.stop()

        # close store(aka. leveldb) after cleanup all threads
        # because hard crashes may occur.
        # https://plyvel.readthedocs.io/en/latest/api.html#DB.close
        self.blockchain.close_blockchain_store()

    def add_complain(self, vote: LeaderVote):
        util.logger.debug(f"vote({vote})")

        if not self.preps_contain(vote.rep):
            util.logger.debug(f"ignore vote from unknown prep: {vote.rep.hex_hx()}")
            return

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

        complain_kwargs = {
            "complain_vote": fail_vote_dumped,
            "channel": self.channel_name
        }

        if conf.RECOVERY_MODE:
            complain_kwargs["from_recovery"] = True

        request = loopchain_pb2.ComplainLeaderRequest(**complain_kwargs)

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

        complain_kwargs = {
            "complain_vote": leader_vote_dumped,
            "channel": self.channel_name
        }

        if conf.RECOVERY_MODE:
            complain_kwargs["from_recovery"] = True

        request = loopchain_pb2.ComplainLeaderRequest(**complain_kwargs)

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
            if self.is_shutdown_block():
                self.start_suspend()
                return

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

    def preps_contain(self, peer_address: ExternalAddress) -> bool:
        last_block = self.blockchain.last_block
        if last_block:
            preps = self.blockchain.find_preps_addresses_by_roothash(last_block.header.revealed_next_reps_hash)
            util.logger.debug(f"peer_addr: {peer_address}, preps: {preps}")
            return peer_address in preps

        return False

    def is_shutdown_block(self) -> bool:
        return self.blockchain.is_shutdown_block()

    def start_suspend(self):
        self.__channel_service.state_machine.suspend()
        self.blockchain.add_shutdown_unconfirmed_block()
