import abc
from typing import Tuple, Dict


class PeerBridgeBase(abc.ABC):

    @abc.abstractmethod
    def channel_get_status_data(self, channel_name, request):
        pass

    @abc.abstractmethod
    def channel_mq_status_data(self, channel_name) -> Dict:
        pass

    @abc.abstractmethod
    def channel_complain_leader(self, channel_name: str, complain_vote: str):
        pass

    @abc.abstractmethod
    def channel_tx_receiver_add_tx_list(self, channel_name, request):
        pass

    @abc.abstractmethod
    def channel_announce_unconfirmed_block(self, channel_name, block, round_):
        pass

    @abc.abstractmethod
    def channel_block_sync(self, channel_name, block_hash, block_height) -> Tuple:
        pass

    @abc.abstractmethod
    def channel_vote_unconfirmed_block(self, channel_name, vote_dumped):
        pass
