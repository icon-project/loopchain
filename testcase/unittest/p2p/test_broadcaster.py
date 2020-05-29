import pytest

from loopchain.p2p.broadcaster import Broadcaster


@pytest.fixture
def bc():
    """Init and start _Broadcaster"""
    channel = "test_channel"
    self_target = "peer_target"

    broadcaster = Broadcaster(channel, self_target)
    return broadcaster


class TestBroadcaster:
    def test_handler_update_audience(self, bc, mocker):
        # Mock stubmanager to avoid actual grpc stub initialized.
        mocker.patch("loopchain.p2p.stub_manager.StubManager")

        audience_targets = [f"endpoint:{i}" for i in range(5)]

        assert not bc._Broadcaster__audience

        bc.update_audience(audience_targets)
        assert bc._Broadcaster__audience
        assert len(bc._Broadcaster__audience) == len(audience_targets)

    def test_handler_update_audience_twice_and_updated_with_new_audiences(self, bc, mocker):
        # Mock stubmanager to avoid actual grpc stub initialized.
        mocker.patch("loopchain.p2p.stub_manager.StubManager")

        expected_audience_count = 5
        new_audience_start_at = 2
        new_audience_end_at = new_audience_start_at + expected_audience_count

        orig_audience_targets = [f"endpoint:{i}" for i in range(expected_audience_count)]
        new_audience_targets = [f"endpoint:{i}" for i in range(new_audience_start_at, new_audience_end_at)]
        assert len(orig_audience_targets) == len(new_audience_targets)  # expected 5 audiences

        audience_list: dict = bc._Broadcaster__audience
        assert not audience_list

        # Add first time
        bc.update_audience(orig_audience_targets)
        assert audience_list
        assert len(audience_list) == len(orig_audience_targets)

        for audience in orig_audience_targets:
            assert audience in audience_list.keys()
        for common_audience in new_audience_targets[:new_audience_start_at]:
            assert common_audience in audience_list.keys()
        for not_yet_updated_audience in new_audience_targets[new_audience_start_at+1:]:
            assert not_yet_updated_audience not in audience_list.keys()

        # Add second time
        bc.update_audience(new_audience_targets)
        assert len(audience_list) == len(new_audience_targets)

        for removed_audience in orig_audience_targets[:new_audience_start_at]:
            assert removed_audience not in audience_list.keys()
        for updated_audience in new_audience_targets:
            assert updated_audience in audience_list.keys()
