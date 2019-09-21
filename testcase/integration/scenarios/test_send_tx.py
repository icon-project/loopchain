import pytest
from iconsdk.wallet.wallet import KeyWallet

from loopchain import configure as conf
from loopchain import utils
from loopchain.blockchain.blocks import v0_1a, v0_3
from loopchain.blockchain.blocks.block_verifier import BlockVerifier
from loopchain.blockchain.transactions import TransactionVersioner
from testcase.integration.configure.config_generator import ConfigGenerator
from testcase.integration.helper.request import get_block, send_tx, get_tx_by_hash, get_last_block_height

peer_count = 4
channel_count = 2
port_list = [9000, 9100, 9200, 9300]
channel_list = ["channel_0", "channel_1"]


class TestGenerateVariousBlockVersions:
    config: ConfigGenerator = None
    tx_hash_by_channel = {}

    HEIGHT_FROM_V0_1a = 0
    HEIGHT_FROM_V0_3 = 10
    HEIGHT_WAIT_UNTIL = 15

    @pytest.fixture(scope="class", autouse=True)
    def setup(self, config_factory_class_scoped, loopchain):
        config: ConfigGenerator = config_factory_class_scoped()
        config.generate_channel_configs(how_many=channel_count,
                                        height_v0_1a=TestGenerateVariousBlockVersions.HEIGHT_FROM_V0_1a,
                                        height_v0_3=TestGenerateVariousBlockVersions.HEIGHT_FROM_V0_3)
        config.generate_peer_configs(how_many=peer_count)
        config.generate_channel_manage_data()
        config.generate_genesis_data()
        config.write()

        TestGenerateVariousBlockVersions.config = config

        assert loopchain.run(config)

    @pytest.mark.parametrize("channel_name", channel_list)
    @pytest.mark.parametrize("port", port_list)
    def test_check_genesis_block(self, port, channel_name):
        """Check Genesis Block before test starts."""
        endpoint = utils.normalize_request_url(str(port), conf.ApiVersion.v3, channel_name)
        block = get_block(endpoint=endpoint, nth_block=0, block_version=v0_1a.version)

        genesis_tx = list(block.body.transactions.values())[0]
        genesis_data = TestGenerateVariousBlockVersions.config.genesis_data.generate()
        expected_data = genesis_data["transaction_data"]

        assert expected_data["accounts"] == genesis_tx.raw_data["accounts"]
        assert expected_data["message"] == genesis_tx.raw_data["message"]
        assert expected_data["nid"] == genesis_tx.raw_data["nid"]

    @pytest.mark.parametrize("channel_name", ["channel_0", "channel_1"])
    def test_wait_for_target_height(self, channel_name):
        import time

        endpoint = utils.normalize_request_url("9000", conf.ApiVersion.v3, channel_name)
        retry_count = 0
        interval_sleep_sec = 1
        max_retry = (interval_sleep_sec + 2) * TestGenerateVariousBlockVersions.HEIGHT_WAIT_UNTIL
        is_reached = False

        while not is_reached:
            if retry_count >= max_retry:
                assert False

            block_height = get_last_block_height(endpoint)
            if block_height >= TestGenerateVariousBlockVersions.HEIGHT_WAIT_UNTIL:
                is_reached = True
            else:
                retry_count += 1
                time.sleep(interval_sleep_sec)

        assert "Test Passed!"


class TestSendTx:
    config: ConfigGenerator = None
    tx_hash_by_channel = {}

    @pytest.fixture(scope="class", autouse=True)
    def setup(self, config_factory_class_scoped, loopchain):
        config: ConfigGenerator = config_factory_class_scoped()
        config.generate_all(channel_count=channel_count, peer_count=peer_count)
        config.write()

        TestSendTx.config = config

        assert loopchain.run(config)

    def test_please_wait_for_running_nodes(self):
        pass

    @pytest.mark.parametrize("channel_name", channel_list)
    def test_send_tx_icx(self, channel_name):
        """Test for `icx_sendTransaction`."""
        config = TestSendTx.config
        first_account = config.genesis_data.accounts[0]
        wallet: KeyWallet = first_account.wallet

        url = utils.normalize_request_url("9000", conf.ApiVersion.v3, channel_name)
        tx_hash = send_tx(endpoint=url, wallet=wallet)

        assert tx_hash.startswith("0x")
        TestSendTx.tx_hash_by_channel[channel_name] = tx_hash

    @pytest.mark.parametrize("channel_name", channel_list)
    @pytest.mark.parametrize("port", port_list)
    def test_tx_reached_consensus(self, port, channel_name):
        """Find tx_hash from given endpoint."""
        endpoint = utils.normalize_request_url(str(port), conf.ApiVersion.v3, channel_name)
        expected_tx = TestSendTx.tx_hash_by_channel[channel_name]
        tx_result = get_tx_by_hash(endpoint=endpoint, tx_hash=expected_tx)

        assert tx_result

    @pytest.mark.parametrize("channel_name", channel_list)
    @pytest.mark.parametrize("port", port_list)
    def test_verify_block_with_latest_block(self, port, channel_name):
        """Verify lastest block."""
        block_version = v0_3.version
        endpoint = utils.normalize_request_url("9000", conf.ApiVersion.v3, channel_name)

        block = get_block(endpoint=endpoint, block_version=block_version)

        block_verifier = BlockVerifier.new(block_version, TransactionVersioner())
        block_verifier.verify_transactions(block)

        assert True
