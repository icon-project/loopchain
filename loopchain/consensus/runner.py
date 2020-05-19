"""Consensus (lft) execution and event handling"""
import json
import zlib
from typing import TYPE_CHECKING, List

from lft.consensus import Consensus
from lft.consensus.events import BroadcastDataEvent, BroadcastVoteEvent, InitializeEvent, RoundEndEvent, RoundStartEvent
from lft.event import EventSystem, EventRegister
from lft.event.mediators import DelayedEventMediator

from loopchain import configure_default as conf
from loopchain import utils
from loopchain.blockchain.epoch3 import LoopchainEpoch
from loopchain.blockchain.types import ExternalAddress
from loopchain.blockchain.votes.v1_0 import BlockVoteFactory
from loopchain.channel.channel_property import ChannelProperty
from loopchain.protos import loopchain_pb2

if TYPE_CHECKING:
    from loopchain.baseservice import BroadcastScheduler
    from lft.consensus.messages.data import DataFactory
    from lft.consensus.messages.vote import VoteFactory
    from loopchain.blockchain.blocks.v1_0 import Block, BlockFactory
    from loopchain.blockchain.blocks.v1_0 import BlockVote
    from loopchain.blockchain import BlockManager


class ConsensusRunner(EventRegister):
    def __init__(self,
                 node_id: 'ExternalAddress',
                 event_system: 'EventSystem',
                 data_factory: 'DataFactory',
                 vote_factory: 'VoteFactory',
                 broadcast_scheduler: 'BroadcastScheduler',
                 block_manager):
        super().__init__(event_system.simulator)
        self.broadcast_scheduler = broadcast_scheduler
        self.event_system = event_system
        self.consensus = Consensus(self.event_system, node_id, data_factory, vote_factory)
        self._block_manager: 'BlockManager' = block_manager

        # FIXME
        self._block_factory: 'BlockFactory' = data_factory
        self._vote_factory: 'BlockVoteFactory' = vote_factory

    def start(self, event: InitializeEvent):
        utils.logger.notice(f"ConsensusRunner start")

        self.event_system.start(blocking=False)
        self.event_system.simulator.raise_event(event)

    async def _on_event_broadcast_data(self, event: BroadcastDataEvent):
        # call broadcast block
        utils.logger.notice(f"_on_event_broadcast_data")

        target_reps_hash = ChannelProperty().crep_root_hash  # FIXME
        self._block_manager._send_unconfirmed_block(
            block_=event.data,
            target_reps_hash=target_reps_hash,
            round_=event.data.round_num
        )

    async def _on_event_broadcast_vote(self, event: BroadcastVoteEvent):
        # call broadcast vote
        utils.logger.notice(f"_on_event_broadcast_vote")

        vote_dumped = self._vote_dumps(event.vote)
        block_vote = loopchain_pb2.BlockVote(vote=vote_dumped, channel=ChannelProperty().name)

        target_reps_hash = ChannelProperty().crep_root_hash  # FIXME

        self.broadcast_scheduler.schedule_broadcast(
            "VoteUnconfirmedBlock",
            block_vote,
            reps_hash=target_reps_hash
        )

    async def _on_init_event(self, init_event: InitializeEvent):
        utils.logger.notice(f"_on_init_event")

    async def _on_round_end_event(self, round_end_event: RoundEndEvent):
        utils.logger.notice(f"_on_round_end_event")

        await self._write_block(round_end_event)
        await self._round_start(round_end_event)

    # FIXME: Temporary
    async def _write_block(self, round_end_event):
        utils.logger.notice(f"> EPOCH // ROUND ({round_end_event.epoch_num} // {round_end_event.round_num})")

        if round_end_event.is_success:
            consensus_db_pool = self.consensus._data_pool  # FIXME
            blockchain = self._block_manager.blockchain
            db = blockchain.blockchain_store

            try:
                block: 'Block' = consensus_db_pool.get_data(round_end_event.commit_id)
            except KeyError:
                utils.logger.warning(f"Block({round_end_event.commit_id}) does not exists in Consensus's DataPool.")
            else:
                utils.logger.notice(f"> ADDED Block : {block.header.hash}")
                block_hash_encoded = block.header.hash.hex().encode(encoding='UTF-8')
                block_serialized = block.serialize()["!data"]
                block_serialized = json.dumps(block_serialized).encode(encoding='UTF-8')

                batch = db.WriteBatch()
                batch.put(block_hash_encoded, block_serialized)
                batch.put(blockchain.LAST_BLOCK_KEY, block_hash_encoded)
                batch.put(
                    blockchain.BLOCK_HEIGHT_KEY +
                    block.header.height.to_bytes(conf.BLOCK_HEIGHT_BYTES_LEN, byteorder='big'),
                    block_hash_encoded
                )
                batch.write()

    # FIXME: Temporary
    async def _round_start(self, event: RoundEndEvent):
        voters = self._get_next_valiators()
        epoch1 = LoopchainEpoch(num=1, voters=voters)
        next_round = event.round_num + 1

        round_start_event = RoundStartEvent(
            epoch=epoch1,
            round_num=next_round
        )
        round_start_event.deterministic = False
        mediator = self.event_system.get_mediator(DelayedEventMediator)
        mediator.execute(0.5, round_start_event)

    async def _start_new_round(self):
        utils.logger.notice(f"_start_new_round")

    _handler_prototypes = {
        BroadcastDataEvent: _on_event_broadcast_data,
        BroadcastVoteEvent: _on_event_broadcast_vote,
        InitializeEvent: _on_init_event,
        RoundEndEvent: _on_round_end_event
    }

    def _get_next_valiators(self) -> List[ExternalAddress]:
        validators = [
            "hxdf93e48a747fac042460f1a7c349d4a3082db0e0",
            "hx11e5fca16d2e429e354fa8b23ef77d65198cd258",
            "hx3d1f7566c28cf757f820374f79a1ef839d2ea404",
            "hxeb5b66a86321dc1a5b3716cee8c9f53f38395eaa",
            "hx2f38e47c7ef71ec113415d22b48d9da799aa8eef",
            "hx0bccda1a3d864c949f425959bbbf9040cc0a1622",
            "hx21da9f153bb749e1c38c71d067d4d47853804a40",
        ]
        return [ExternalAddress.fromhex_address(validator) for validator in validators]

    def _vote_dumps(self, vote: 'BlockVote') -> bytes:
        vote_dumped: dict = vote.serialize()["!data"]
        return json.dumps(vote_dumped)
