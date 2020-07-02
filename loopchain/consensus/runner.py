"""Consensus (lft) execution and event handling"""
import json
from typing import TYPE_CHECKING

from lft.consensus import Consensus
from lft.consensus.events import BroadcastDataEvent, BroadcastVoteEvent, InitializeEvent, RoundEndEvent, RoundStartEvent
from lft.event import EventSystem, EventRegister
from lft.event.mediators import DelayedEventMediator

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
        self._block_factory: 'BlockFactory' = data_factory
        self._vote_factory: 'BlockVoteFactory' = vote_factory

    def start(self, event: InitializeEvent):
        self.event_system.start(blocking=False)
        self.event_system.simulator.raise_event(event)

    async def _on_event_broadcast_data(self, event: BroadcastDataEvent):
        target_reps_hash = ChannelProperty().crep_root_hash  # FIXME
        self._block_manager.send_unconfirmed_block(
            block_=event.data,
            target_reps_hash=target_reps_hash,
            round_=event.data.round_num
        )

    async def _on_event_broadcast_vote(self, event: BroadcastVoteEvent):
        vote_dumped = self._vote_dumps(event.vote)
        block_vote = loopchain_pb2.BlockVote(vote=vote_dumped, channel=ChannelProperty().name)

        target_reps_hash = ChannelProperty().crep_root_hash  # FIXME

        self.broadcast_scheduler.schedule_broadcast(
            "VoteUnconfirmedBlock",
            block_vote,
            reps_hash=target_reps_hash
        )

    async def _on_round_end_event(self, round_end_event: RoundEndEvent):
        utils.logger.notice(f"_on_round_end_event")

        await self._write_block(round_end_event)
        await self._round_start(round_end_event)

    # FIXME: Temporary
    async def _write_block(self, round_end_event):
        """Write Block 1.0. (Temporary)

        Note that RoundEndEvent can be raised when the node restarted. Avoid rewriting block which is committed.
        """
        if round_end_event.is_success and not self._block_manager.blockchain.find_block_by_hash(round_end_event.commit_id):
            consensus_db_pool = self.consensus._data_pool  # FIXME
            blockchain = self._block_manager.blockchain

            try:
                block: 'Block' = consensus_db_pool.get_data(round_end_event.commit_id)
            except KeyError:
                utils.logger.warning(f"Block({round_end_event.commit_id}) does not exists in Consensus's DataPool.")
            else:
                vote_pool = self.consensus._vote_pool
                votes = tuple(vote_pool.get_votes(block.header.epoch, block.header.round))
                blockchain.add_block(
                    block=block, confirm_info=votes, need_to_score_invoke=False, force_write_block=True
                )

    # FIXME: Temporary
    async def _round_start(self, event: RoundEndEvent):
        epoch1 = LoopchainEpoch(num=1, voters=(ChannelProperty().peer_address,))
        next_round = event.round_num + 1

        round_start_event = RoundStartEvent(
            epoch=epoch1,
            round_num=next_round
        )
        round_start_event.deterministic = False
        mediator = self.event_system.get_mediator(DelayedEventMediator)
        mediator.execute(0.5, round_start_event)

    _handler_prototypes = {
        BroadcastDataEvent: _on_event_broadcast_data,
        BroadcastVoteEvent: _on_event_broadcast_vote,
        RoundEndEvent: _on_round_end_event
    }

    def _vote_dumps(self, vote: 'BlockVote') -> bytes:
        vote_dumped: dict = vote.serialize()["!data"]
        return json.dumps(vote_dumped)
