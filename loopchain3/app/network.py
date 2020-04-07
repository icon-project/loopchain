import random

from typing import TYPE_CHECKING, DefaultDict, Set
from lft.event import EventRegister, EventSystem
from lft.event.mediators import DelayedEventMediator
from lft.consensus.events import (BroadcastDataEvent, BroadcastVoteEvent,
                                  ReceiveDataEvent, ReceiveVoteEvent)

if TYPE_CHECKING:
    from lft.consensus.messages.data import Data
    from lft.consensus.messages.vote import Vote

__all__ = ("Network", )

Datums = DefaultDict[int, Set['Data']]
Votes = DefaultDict[int, Set['Vote']]


class Network(EventRegister):
    def __init__(self, event_system: EventSystem):
        super().__init__(event_system.simulator)
        self._peers: Set['Network'] = set()
        self._delayed_mediator = event_system.get_mediator(DelayedEventMediator)

    def add_peer(self, peer: 'Network'):
        self._peers.add(peer)

    def remove_peer(self, peer: 'Network'):
        self._peers.remove(peer)

    def receive_data(self, data: 'Data'):
        event = ReceiveDataEvent(data)
        event.deterministic = False

        delay = self.random_delay()
        self._delayed_mediator.execute(delay, event)

    def receive_vote(self, vote: 'Vote'):
        event = ReceiveVoteEvent(vote)
        event.deterministic = False

        delay = self.random_delay()
        self._delayed_mediator.execute(delay, event)

    def broadcast_data(self, data: 'Data'):
        for peer in self._peers:
            peer.receive_data(data)

    def broadcast_vote(self, vote: 'Vote'):
        for peer in self._peers:
            peer.receive_vote(vote)

    def _on_event_broadcast_data(self, event: 'BroadcastDataEvent'):
        self.broadcast_data(event.data)

    def _on_event_broadcast_vote(self, event: 'BroadcastVoteEvent'):
        self.broadcast_vote(event.vote)

    @classmethod
    def random_delay(cls):
        return random.randint(0, 10000) / 10000

    _handler_prototypes = {
        BroadcastDataEvent: _on_event_broadcast_data,
        BroadcastVoteEvent: _on_event_broadcast_vote
    }
