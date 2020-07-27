"""Consensus (lft) execution and event handling"""
import asyncio
import json
import time
from typing import TYPE_CHECKING, Sequence, Iterator, cast, List

from loopchain import configure as conf

from lft.consensus import Consensus
from lft.consensus.epoch import EpochPool
from lft.consensus.events import BroadcastDataEvent, BroadcastVoteEvent, InitializeEvent, RoundEndEvent, RoundStartEvent
from lft.consensus.events import ReceiveDataEvent, ReceiveVoteEvent
from lft.event import EventSystem, EventRegister
from lft.event.mediators import DelayedEventMediator

from loopchain import utils, configure as conf
from loopchain.blockchain.blocks.v1_0 import Block, BlockFactory, BlockBuilder, BlockHeader
from loopchain.blockchain.epoch3 import LoopchainEpoch
from loopchain.blockchain.invoke_result import InvokePool
from loopchain.blockchain.transactions import TransactionBuilder
from loopchain.blockchain.types import ExternalAddress, Hash32
from loopchain.blockchain.votes.v1_0 import BlockVote, BlockVoteFactory
from loopchain.channel.channel_property import ChannelProperty
from loopchain.protos import loopchain_pb2

from loopchain.channel.channel_property import ChannelProperty

if TYPE_CHECKING:
    from loopchain.baseservice import BroadcastScheduler
    from loopchain.baseservice.aging_cache import AgingCache
    from loopchain.peer.block_manager import BlockManager
    from loopchain.store.key_value_store import KeyValueStore, KeyValueStoreWriteBatch


class ConsensusRunner(EventRegister):
    def __init__(self,
                 event_system: 'EventSystem',
                 tx_queue: 'AgingCache',
                 broadcast_scheduler: 'BroadcastScheduler',
                 block_manager: 'BlockManager'):
        super().__init__(event_system.simulator)

        self._block_manager: 'BlockManager' = block_manager
        self._invoke_pool: InvokePool = InvokePool(block_manager.blockchain)
        self.broadcast_scheduler = broadcast_scheduler
        self.event_system = event_system
        self._block_factory: 'BlockFactory' = BlockFactory(
            epoch_pool_with_app=EpochPool(),
            tx_queue=tx_queue,
            blockchain=self._block_manager.blockchain,
            tx_versioner=self._block_manager.blockchain.tx_versioner,
            invoke_pool=self._invoke_pool,
            signer=ChannelProperty().peer_auth
        )
        self._vote_factory: 'BlockVoteFactory' = BlockVoteFactory(
            invoke_result_pool=self._invoke_pool,
            signer=ChannelProperty().peer_auth
        )
        self.consensus = Consensus(
            self.event_system, ChannelProperty().peer_address, self._block_factory, self._vote_factory
        )

        self._loop = asyncio.get_event_loop()

        self._is_broadcasting: bool = False
        self._is_voting: bool = False
        self._last_block_height = 0
        self._height_info_other_nodes = dict()
        self._data_info_other_nodes = dict()
        self._vote_info_other_nodes = dict()
        self._max_height_in_nodes = 0
        self._sync_mode = False

        self._request_history_list = dict()
        self._target_idx = 0
        self._stub_list = list()

    async def _management_stub(self, status: str = 'init'):
        self._target_list = self._block_manager.get_target_list()
        for target in self._target_list:
            util.logger.debug(f"try to target({target})")
            channel = GRPCHelper().create_client_channel(target)
            self._stub_list.append(loopchain_pb2_grpc.PeerServiceStub(channel))

    async def start(self, channel_service):
        self._loop.create_task(self.lft_start(channel_service))
        self._loop.create_task(self.sync_start())

    async def lft_start(self, channel_service):
        event = await self._create_initialize_event(channel_service)
        self.event_system.start(blocking=False)
        self.event_system.simulator.raise_event(event)

    async def _create_initialize_event(self, channel_service) -> InitializeEvent:
        initial_epoches = []
        initial_blocks = []
        initial_votes = []

        blockchain = self._block_manager.blockchain
        last_commit_block: Block = blockchain.last_block

        if last_commit_block:  # Not Genesis Block
            commit_id = last_commit_block.header.hash
            initial_blocks.append(last_commit_block)

            curr_epoch = LoopchainEpoch(
                num=last_commit_block.header.epoch,
                voters=blockchain.find_preps_addresses_by_header(last_commit_block.header.next_validators_hash)
            )
            initial_epoches.append(curr_epoch)

            candidate_block: Block = self.find_candidate_block_by_height(last_commit_block.header.height+1)
            self._invoke_pool.invoke(candidate_block)
            initial_blocks.append(candidate_block)

            last_block_votes = self._find_votes_by_hash(last_commit_block.header.hash)
            last_candidate_votes = self._find_votes_by_hash(candidate_block.header.hash)
            initial_votes.extend(last_block_votes)
            initial_votes.extend(last_candidate_votes)

        else:  # Need to create Genesis Block
            candidate_block: Block = self._generate_genesis_block()
            channel_service.update_nid()

            self._invoke_pool.genesis_invoke(candidate_block)
            initial_blocks.append(candidate_block)

            initial_epoches.append(LoopchainEpoch(num=0, voters=()))
            voters = blockchain.find_preps_addresses_by_roothash(ChannelProperty().crep_root_hash)
            initial_epoches.append(LoopchainEpoch(num=1, voters=voters))
            commit_id = candidate_block.header.prev_hash

        event = InitializeEvent(
            commit_id=commit_id,
            epoch_pool=initial_epoches,
            data_pool=initial_blocks,
            vote_pool=initial_votes
        )
        event.deterministic = False

        return event

    def _generate_genesis_block(self):
        tx_versioner = self._block_manager.blockchain.tx_versioner

        block_builder = BlockBuilder.new(BlockHeader.version, tx_versioner)
        block_builder.peer_id = ExternalAddress.empty()
        block_builder.fixed_timestamp = 0
        block_builder.prev_votes = []
        block_builder.prev_state_hash = Hash32.empty()

        tx = self._generate_genesis_tx(tx_versioner)
        block_builder.transactions[tx.hash] = tx

        block_builder.height = 0
        block_builder.prev_hash = Hash32.empty()
        block_builder.signer = None

        validators_hash = ChannelProperty().crep_root_hash
        block_builder.validators_hash = validators_hash
        block_builder.next_validators = self._block_manager.blockchain.find_preps_addresses_by_roothash(validators_hash)

        block_builder.epoch = 0
        block_builder.round = 0

        return block_builder.build()

    def _generate_genesis_tx(self, tx_versioner):
        genesis_data_path = conf.CHANNEL_OPTION[ChannelProperty().name]["genesis_data_path"]
        utils.logger.spam(f"Try to load a file of initial genesis block from ({genesis_data_path})")
        with open(genesis_data_path, encoding="utf-8") as json_file:
            tx_info = json.load(json_file)["transaction_data"]
            nid = tx_info["nid"]
            ChannelProperty().nid = nid

        tx_builder = TransactionBuilder.new("genesis", "", tx_versioner)
        nid = tx_info.get("nid")
        self._block_manager.blockchain.put_nid(nid)
        tx_builder.nid = int(nid, 16) if nid else None
        tx_builder.accounts = tx_info["accounts"]
        tx_builder.message = tx_info["message"]

        return tx_builder.build(False)

    async def _on_event_broadcast_data(self, event: BroadcastDataEvent):
        if self._block_manager.blockchain.try_update_last_unconfirmed_block(event.data):
            self._loop.create_task(self._repeat_broadcast_block(event.data))

    async def _repeat_broadcast_block(self, block: "Block"):
        self._is_broadcasting = True
        while self._is_broadcasting:
            target_reps_hash = ChannelProperty().crep_root_hash  # FIXME
            self._block_manager.send_unconfirmed_block(
                block_=block,
                target_reps_hash=target_reps_hash,
                round_=block.round_num
            )
            await asyncio.sleep(conf.INTERVAL_BLOCKGENERATION)

    async def _on_event_broadcast_vote(self, event: BroadcastVoteEvent):
        vote_dumped = self._vote_dumps(event.vote)
        block_vote = loopchain_pb2.BlockVote(vote=vote_dumped, channel=ChannelProperty().name)

        target_reps_hash = ChannelProperty().crep_root_hash  # FIXME

        self._loop.create_task(self._repeat_broadcast_vote(block_vote, target_reps_hash))

    async def _repeat_broadcast_vote(self, block_vote: "BlockVote", target_reps_hash):
        self._is_voting = True
        while self._is_voting:
            self.broadcast_scheduler.schedule_broadcast(
                "VoteUnconfirmedBlock",
                block_vote,
                reps_hash=target_reps_hash
            )
            await asyncio.sleep(conf.INTERVAL_BLOCKGENERATION)

    async def _on_round_end_event(self, round_end_event: RoundEndEvent):
        self._is_broadcasting, self._is_voting = False, False
        await self._write_block(round_end_event)
        await self._round_start(round_end_event)

    # FIXME: Temporary
    async def _write_block(self, round_end_event):
        """Write Block 1.0. (Temporary)

        Note that RoundEndEvent can be raised when the node restarted. Avoid rewriting block which is committed.
        """
        if round_end_event.is_success and not self._block_manager.blockchain.is_block_in_db(round_end_event.commit_id):
            consensus_db_pool = self.consensus._data_pool  # FIXME
            blockchain = self._block_manager.blockchain

            try:
                block: 'Block' = consensus_db_pool.get_data(round_end_event.commit_id)
            except KeyError:
                utils.logger.warning(f"Block({round_end_event.commit_id}) does not exists in Consensus's DataPool.")
            else:
                vote_pool = self.consensus._vote_pool
                votes = tuple(vote_pool.get_votes(block.header.epoch, block.header.round))
                confirm_info = self._serialize_votes(votes)

                candidate_block: 'Block' = consensus_db_pool.get_data(round_end_event.candidate_id)
                candidate_votes: Sequence[BlockVote] = vote_pool.get_votes(
                    epoch_num=candidate_block.header.epoch,
                    round_num=candidate_block.header.round
                )
                self._invoke_if_not(block)
                self._write_candidate_info(candidate_block, candidate_votes)
                blockchain.add_block(
                    block=block, confirm_info=confirm_info, need_to_score_invoke=False, force_write_block=True
                )
                self._last_block_height = block.header.height

    def _invoke_if_not(self, block: "Block"):
        try:
            self._invoke_pool.get_invoke_data(block.header.epoch, block.header.round)
        except KeyError:
            self._invoke_pool.invoke(block)

    def _write_candidate_info(self, candidate_block: 'Block', candidate_votes: Sequence[BlockVote]):
        """Write candidate info in batch."""

        blockchain = self._block_manager.blockchain
        store: 'KeyValueStore' = blockchain.blockchain_store
        batch = store.WriteBatch()

        block_serialized = self._serialize_block(candidate_block)
        candidate_height_key = self._get_candidate_block_key_by_height(candidate_block.header.height)
        batch.put(candidate_height_key, block_serialized)

        block_hash_encoded = candidate_block.header.hash.hex().encode("utf-8")
        votes_serialized = self._serialize_votes(candidate_votes)
        batch.put(blockchain.CONFIRM_INFO_KEY + block_hash_encoded, votes_serialized)

        self._prune_candidate_info_until(candidate_block, batch)
        batch.write()

    def _prune_candidate_info_until(self, candidate_block, batch: 'KeyValueStoreWriteBatch'):
        blockchain = self._block_manager.blockchain
        target_height: int = candidate_block.header.height - 1

        candidate_block_key = self._get_candidate_block_key_by_height(target_height)
        batch.delete(candidate_block_key)

        block_hash_encoded = candidate_block.header.prev_hash.hex().encode("utf-8")
        candidate_vote_key = blockchain.CANDIDATE_CONFIRM_INFO_KEY + block_hash_encoded
        batch.delete(candidate_vote_key)

    def _get_candidate_block_key_by_height(self, height: int):
        candidate_height_key = height.to_bytes(conf.BLOCK_HEIGHT_BYTES_LEN, byteorder="big")

        return self._block_manager.blockchain.LAST_CANDIDATE_KEY + candidate_height_key

    def _find_votes_by_hash(self, block_hash: Hash32) -> Iterator[BlockVote]:
        block_votes: bytes = self._block_manager.blockchain.find_confirm_info_by_hash(block_hash)

        return (BlockVote.deserialize(vote_serialized) for vote_serialized in json.loads(block_votes))

    def _serialize_block(self, block: 'Block'):
        """Serialize Block 1.0 to write in DB."""

        return json.dumps(block.serialize()).encode("utf-8")

    def _serialize_votes(self, votes: Sequence[BlockVote]) -> bytes:
        """Serialize Vote 1.0 to write in DB."""

        confirm_info = [vote.serialize() for vote in votes]
        confirm_info = json.dumps(confirm_info)

        return confirm_info.encode('utf-8')

    def find_candidate_block_by_height(self, height) -> Block:
        candidate_key = self._get_candidate_block_key_by_height(height)
        block_serialized = self._block_manager.blockchain.blockchain_store.get(candidate_key)
        block_serialized = cast(dict, json.loads(block_serialized))

        return Block.deserialize(block_serialized)

    # FIXME: Temporary
    async def _round_start(self, event: RoundEndEvent):
        if event.is_success:
            commit_id = event.commit_id
        elif self._block_manager.blockchain.last_block:
            # Normal failed
            commit_id = self._block_manager.blockchain.last_block.header.hash
        else:
            # Genesis failed
            commit_id = Hash32.empty()

        voters = self._get_next_validators(commit_id)
        epoch1 = LoopchainEpoch(num=1, voters=voters)
        next_round = event.round_num + 1

        round_start_event = RoundStartEvent(
            epoch=epoch1,
            round_num=next_round
        )
        round_start_event.deterministic = False
        mediator = self.event_system.get_mediator(DelayedEventMediator)
        mediator.execute(0.5, round_start_event)

    def update_status(self, peer: str, height: int):
        # TODO: Update height info
        pass

    _handler_prototypes = {
        BroadcastDataEvent: _on_event_broadcast_data,
        BroadcastVoteEvent: _on_event_broadcast_vote,
        RoundEndEvent: _on_round_end_event
    }

    def _get_next_validators(self, block_hash: Hash32) -> List[ExternalAddress]:
        blockchain = self._block_manager.blockchain

        if block_hash == Hash32.empty():  # On Genesis Block
            validators_hash = ChannelProperty().crep_root_hash
        else:
            block: Block = blockchain.find_block_by_hash32(block_hash)
            validators_hash = block.header.next_validators_hash

        return blockchain.find_preps_addresses_by_roothash(validators_hash)

    def _vote_dumps(self, vote: 'BlockVote') -> bytes:
        vote_dumped: dict = vote.serialize()["!data"]
        return json.dumps(vote_dumped)

    def receive_vote(self, vote: 'BlockVote'):
        event = ReceiveVoteEvent(vote)
        self.event_system.simulator.raise_event(event)

    def receive_data(self, unconfirmed_block: 'Block'):
        event = ReceiveDataEvent(unconfirmed_block)
        self.event_system.simulator.raise_event(event)
