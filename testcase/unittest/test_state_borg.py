
import pytest

from loopchain.peer.state_borg import Borg, PeerState


class TestBorg(object):

    @pytest.mark.skip
    def test_borg(self):
        borg1 = Borg()
        borg2 = Borg()

        borg1.state = "Running"

        print(borg1)
        print(borg2)

        assert borg1.state == borg2.state

    def test_peer_state_borg(self):
        print("\n==== peer_borg1 ====")
        peer_borg1 = PeerState()

        peer_borg1.peer_port = 8080
        peer_borg1.peer_target = 'localhost'
        peer_borg1.rest_target = '127.0.0.1:9000'
        peer_borg1.peer_id = 'peer_id'
        peer_borg1.radio_station_target = 'radio_station_target'
        peer_borg1.channel_infos = {'peer': '1231414141', 'order': 1}
        peer_borg1.node_key = b'a2f0c1e9b'
        peer_borg1.status_cache = {'foo': 'bar', 'fooo': 'barr'}

        print(peer_borg1)

        print("\n==== peer_borg2 ====")
        peer_borg2 = PeerState()

        peer_borg2.peer_port = 9000
        peer_borg1.peer_target = '192.168.0.1'
        peer_borg1.peer_id = 'new_peer_id'

        print(peer_borg1)
        print(peer_borg2)

        assert peer_borg1.peer_port == peer_borg2.peer_port
        assert peer_borg1.peer_target == peer_borg2.peer_target
        assert peer_borg1.node_key == peer_borg2.node_key

