from loopchain.baseservice import ScoreResponse, PeerInfo, PeerStatus, PeerObject, ObjectManager
from loopchain.baseservice.aging_cache import AgingCache
from loopchain.blockchain import Block
from loopchain import configure as conf
from loopchain.blockchain.validator import GenesisBlockValidator
from testcase.unittest import test_util


class Mock:
    pass


class PeerServiceMock:
    peer_id = 'peer_id'


class ChannelServiceMock:
    def __init__(self, channel_name):
        self.__channel_name = channel_name

    @property
    def block_manager(self):
        class BlockManagerMock:
            def get_tx_queue(self):
                return AgingCache(max_age_seconds=10)

        return BlockManagerMock()

    def get_channel_option(self):
        channel_option = conf.CHANNEL_OPTION
        return channel_option[self.__channel_name]

    def score_invoke(self, block: Block):
        invoke_result = {}
        for i, tx in enumerate(block.confirmed_transaction_list):
            invoke_result[tx.tx_hash] = {"code": 0}
            if i == 2:
                invoke_result[tx.tx_hash] = {"code": ScoreResponse.EXCEPTION, "message": "for test fail"}
        return invoke_result

    def score_write_precommit_state(self, block: Block):
        pass


class PeerManagerMock:
    def __init__(self, peer_auth):
        self.__peer_auth = peer_auth

    def get_leader_object(self):
        mock_info = PeerInfo(peer_id="peer_id", group_id='a', target="192.0.0.1:1234", status=PeerStatus.unknown,
                             cert=self.__peer_auth.peer_cert, order=0)
        mock_peer_object = PeerObject(list(conf.CHANNEL_OPTION)[0], mock_info)
        return mock_peer_object


def set_mock(test):
    peer_auth = test_util.create_default_peer_auth()
    test.peer_auth = peer_auth
    peer_service_mock = PeerServiceMock()
    peer_service_mock.peer_manager = PeerManagerMock(peer_auth)
    peer_service_mock.channel_service = ChannelServiceMock(conf.LOOPCHAIN_DEFAULT_CHANNEL)

    ObjectManager().peer_service = peer_service_mock
    ObjectManager().channel_service = peer_service_mock.channel_service
