import time

import pytest

from loopchain import configure as conf
from loopchain.baseservice.node_pool import NodePool
from collections import namedtuple


FetchedStatus = namedtuple("Status", "target, elapsed_time, height")


class TestNodePool:
    CHANNEL_NAME = "icon_dex"
    TEST_STATUS = [
        FetchedStatus(target="127.0.0.1:0", elapsed_time=0.01, height=5),
        FetchedStatus(target="127.0.0.1:1", elapsed_time=0.02, height=4),
        FetchedStatus(target="127.0.0.1:2", elapsed_time=0.03, height=3),
        FetchedStatus(target="127.0.0.1:3", elapsed_time=0.04, height=2),
        FetchedStatus(target="127.0.0.1:4", elapsed_time=0.05, height=1),
    ]

    def get_status_by_endpoint(self, endpoint) -> FetchedStatus:
        """Helper for getting status data matched to given endpoint."""
        return next(status for status in self.TEST_STATUS if status.target == endpoint)

    @pytest.fixture
    def node_pool(self, mocker):
        channel_option = {
            self.CHANNEL_NAME: {
                "radiostations": [status.target for status in self.TEST_STATUS]
            }
        }
        mocker.patch.object(conf, "CHANNEL_OPTION", channel_option)
        node_pool = NodePool(self.CHANNEL_NAME)

        return node_pool

    def test_init_without_rs(self):
        with pytest.raises(RuntimeError, match="radiostations"):
            NodePool(self.CHANNEL_NAME)

    @pytest.mark.skip(reason="Slow")
    def test_concurrent_in_find_nearst(self, node_pool):
        def _mock_fetch_status(endpoint: str):
            port = int(endpoint.split(":")[-1])
            start_time = time.time()
            time.sleep(port)

            result = {
                'target': endpoint,
                'elapsed_time': time.time() - start_time,
                'height': port
            }

            return result

        node_pool._fetch_status = _mock_fetch_status
        node_pool.find()

    def test_fastest_is_nearest_target(self, node_pool):
        def _mock_fetch_status(endpoint: str):
            status: FetchedStatus = self.get_status_by_endpoint(endpoint)
            return {
                'target': status.target,
                'elapsed_time': status.elapsed_time,
                'height': status.height
            }

        node_pool._fetch_status = _mock_fetch_status
        node_pool.find()

        assert node_pool.target == f"http://{self.TEST_STATUS[0].target}"

    def test_remove_current_target_after_find(self, node_pool):
        def _mock_fetch_status(endpoint: str):
            status: FetchedStatus = self.get_status_by_endpoint(endpoint)
            return {
                'target': status.target,
                'elapsed_time': status.elapsed_time,
                'height': status.height
            }

        node_pool._fetch_status = _mock_fetch_status
        node_pool.find()
        assert node_pool.target == f"http://{self.TEST_STATUS[0].target}"

        node_pool.find()
        assert node_pool.target == f"http://{self.TEST_STATUS[1].target}"

    @pytest.mark.parametrize("available_state", ["Vote", "LeaderComplain", "Watch"])
    def test_nodes_must_in_available_states(self, node_pool, available_state):
        def _mock_call(endpoint, status, timeout):
            original_data: FetchedStatus = self.get_status_by_endpoint(endpoint)

            return {
                "state": available_state,
                "block_height": original_data.height
            }

        node_pool._rest_client.call = _mock_call
        node_pool.find()

        assert node_pool.target in (f"http://{status.target}" for status in self.TEST_STATUS)

    @pytest.mark.parametrize("ignored_state", ["BlockGenerate", "SubscribeNetwork"])
    def test_nodes_ignored_if_not_in_available_states(self, node_pool, ignored_state):
        def _mock_call(endpoint, status, timeout):
            original_data: FetchedStatus = self.get_status_by_endpoint(endpoint)

            return {
                "state": ignored_state,
                "block_height": original_data.height
            }

        node_pool._rest_client.call = _mock_call
        node_pool.find()

        assert not node_pool.target
