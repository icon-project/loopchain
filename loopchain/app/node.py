from typing import IO, Dict, Type, OrderedDict
from lft.app.data import DefaultDataFactory
from lft.app.epoch import RotateEpoch
from lft.app.vote import DefaultVoteFactory
from lft.app.network import Network
from lft.app.logger import Logger
from lft.consensus.messages.data import Data
from lft.event import EventSystem, EventMediator
from lft.event.mediators import DelayedEventMediator
from lft.consensus.consensus import Consensus
from lft.consensus.events import RoundStartEvent, RoundEndEvent, InitializeEvent

__all__ = ("Node", )


class Node:
    def __init__(self, node_id: bytes):
        self.node_id = node_id
        self.logger = Logger(node_id).logger
        self.event_system = EventSystem(self.logger)
        self.event_system.set_mediator(DelayedEventMediator)

        self._nodes = None
        self._network = Network(self.event_system)
        self._consensus = Consensus(
            self.event_system,
            self.node_id,
            DefaultDataFactory(self.node_id),
            DefaultVoteFactory(self.node_id)
        )
        self._epoch_num = -1
        self._round_num = -1

        # For store
        self.commit_datums: OrderedDict[int, Data] = OrderedDict()

        self.event_system.simulator.register_handler(InitializeEvent, self._on_init_event)
        self.event_system.simulator.register_handler(RoundEndEvent, self._on_round_end_event)

    async def _on_init_event(self, init_event: InitializeEvent):
        self._nodes = init_event.epoch_pool[-1].voters

    async def _on_round_end_event(self, round_end_event: RoundEndEvent):
        if round_end_event.is_success and round_end_event.commit_id:
            data = self._consensus._data_pool.get_data(round_end_event.commit_id)
            self.commit_datums[data.number] = data

        if (self._epoch_num, self._round_num) > (round_end_event.epoch_num, round_end_event.round_num):
            return
        self._epoch_num = round_end_event.epoch_num
        self._round_num = round_end_event.round_num + 1
        await self._start_new_round()

    async def _start_new_round(self):
        round_start_event = RoundStartEvent(
            epoch=RotateEpoch(1, self._nodes),
            round_num=self._round_num
        )
        round_start_event.deterministic = False
        mediator = self.event_system.get_mediator(DelayedEventMediator)
        mediator.execute(0.5, round_start_event)

    def __del__(self):
        self.close()

    def close(self):
        if self._network:
            self._network.close()
            self._network = None

        if self._consensus:
            self._consensus.close()
            self._consensus = None

        if self.event_system:
            self.event_system.close()
            self.event_system = None

    def start(self, blocking=True):
        self.event_system.start(blocking)

    def start_record(self, record_io: IO, mediator_ios: Dict[Type[EventMediator], IO]=None, blocking=True):
        self.event_system.start_record(record_io, mediator_ios, blocking)

    def start_replay(self, record_io: IO, mediator_ios: Dict[Type[EventMediator], IO]=None, blocking=True):
        self.event_system.start_replay(record_io, mediator_ios, blocking)

    def register_peer(self, peer: 'Node'):
        self._network.add_peer(peer._network)

    def unregister_peer(self, peer: 'Node'):
        self._network.remove_peer(peer._network)
