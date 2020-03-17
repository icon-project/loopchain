import asyncio
from typing import List, Optional
from lft.app.ui.listener import Listener
from lft.consensus.events import InitializeEvent
from loopchain.app.node import Node
from loopchain.app.data import DefaultData
from loopchain.app.epoch import RotateEpoch
from loopchain.blockchain import ExternalAddress


__all__ = ("App",)


class App:
    def __init__(self, id_: ExternalAddress):
        self.node = Node(id_)
        self.nodes = [self.node]  # for console
        self.listener = Listener(self)
        self.loop: Optional[asyncio.AbstractEventLoop] = asyncio.get_event_loop()

    def __del__(self):
        self.close()

    def start(self):
        peers = []
        self._connect_nodes(peers)
        self._raise_init_event([self.node] + peers)

        self.listener.start()

        try:
            self.node.start()
        except RuntimeError:
            pass
        finally:
            self.close()

    def _connect_nodes(self, peers: List[Node]):
        for peer in peers:
            self.node.register_peer(peer)

    def close(self):
        self.listener.stop()
        if self.loop and self.loop.is_running():
            self.loop.stop()

    def _raise_init_event(self, nodes: List[Node]):
        genesis_round_num = 0
        genesis_epoch_num = 0
        genesis_data = DefaultData(
            id_=b'genesis',
            prev_id=b'',
            proposer_id=b'',
            number=0,
            epoch_num=genesis_epoch_num,
            round_num=genesis_round_num,
            prev_votes=()
        )

        data_pool = [genesis_data]
        vote_pool = []
        epoch_pool = [RotateEpoch(0, []), RotateEpoch(1, tuple(node.node_id for node in nodes))]
        event = InitializeEvent(genesis_data.prev_id, epoch_pool, data_pool, vote_pool)
        event.deterministic = False
        self.node.event_system.simulator.raise_event(event)
