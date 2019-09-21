import json
import os
from typing import List

import pytest

from loopchain.blockchain.blocks import v0_1a
from loopchain.blockchain.blocks import v0_3
from testcase.integration.configure.config_generator import (
    Account, ChannelConfigKey, ChannelConfig, PeerConfigKey, PeerConfig, ChannelManageData, GenesisData, ConfigGenerator
)
from testcase.integration.configure.exceptions import (
    NotFoundChannelConfig, NotFoundBlockVersions, NotFoundChannelManageDataPath, NotFoundPeerConfig
)


class _Params:
    CHANNEL_NAME_LIST = [
        ["test_one_channel"],
        ["ICON_DEX", "DEX_ICON"],
        ["ICON_DEX", "NOCI", "THIRD_cHaNnEl"],
    ]
    CHANNEL_PEER_COUNT = [
        (2, 7), (1, 1), (4, 9)
    ]
    NUM_LIST = [1, 4, 8]
    ACCOUNT_COUNT = [4, 9, 20]


class TestAccount:
    def test_has_valid_name(self, account_factory):
        key_name = "test_key"

        account = account_factory(name=key_name)
        assert account.name == key_name

    def test_has_valid_address(self, account_factory):
        """Check that wallet generator has no issues in making accounts."""
        account = account_factory()

        assert account.address.startswith("hx")

    def test_has_correct_balance(self, account_factory):
        show_me_the_money = "0x99999999999999999999999999999999"
        account: Account = account_factory(balance=show_me_the_money)

        assert account._balance == show_me_the_money

    def test_has_valid_key_path(self, account_factory):
        account = account_factory()

        assert os.path.exists(account.path)

    def test_has_valid_password(self, account_factory):
        password = "password"

        account = account_factory(password=password)
        assert account.password == password

    def test_get_config_has_valid_form(self, account_factory):
        account: Account = account_factory()
        result = account.generate()

        assert isinstance(result, dict)
        for key in ["name", "address", "balance"]:
            assert key in result


class TestChannelConfig:
    def test_channel_has_valid_name(self, channel_config_factory):
        expected_channel_name = "icon_test_dex"
        channel_config: ChannelConfig = channel_config_factory(expected_channel_name)

        assert channel_config.name == expected_channel_name

    def test_generate_without_set_block_versions_raises_exc(self, channel_config_factory):
        channel_config: ChannelConfig = channel_config_factory()
        channel_config._block_versions = {}

        with pytest.raises(NotFoundBlockVersions):
            channel_config.generate()

    @pytest.mark.parametrize("height_v0_1a, height_v0_3", [
        (0, 1), (5, 10)
    ])
    def test_set_block_version_height(self, channel_config_factory, height_v0_1a, height_v0_3):
        channel_config: ChannelConfig = channel_config_factory()
        channel_config.set_block_version_heights(height_v0_1a=height_v0_1a, height_v0_3=height_v0_3)

        config_dict = channel_config.generate()
        block_versions: dict = config_dict[ChannelConfigKey.BLOCK_VERSIONS.value]
        assert block_versions[v0_1a.version] == height_v0_1a
        assert block_versions[v0_3.version] == height_v0_3

    def test_ignore_block_version_if_negative_num(self, channel_config_factory):
        channel_config: ChannelConfig = channel_config_factory()

        channel_config.set_block_version_heights(height_v0_1a=0, height_v0_3=-1)
        config_dict = channel_config.generate()
        block_versions: dict = config_dict[ChannelConfigKey.BLOCK_VERSIONS.value]

        assert block_versions.get(v0_1a.version) == 0
        assert not block_versions.get(v0_3.version)

    def test_set_genesis_data_path(self, channel_config_factory):
        channel_config: ChannelConfig = channel_config_factory()

        expected_path = "/path/created/for/the/test.json"
        channel_config.genesis_data_path = expected_path
        config_dict = channel_config.generate()

        assert config_dict.get("genesis_data_path") == expected_path

    def test_config_has_no_genesis_data_path_if_not_set_path(self, channel_config_factory):
        channel_config = channel_config_factory()
        config_dict = channel_config.generate()
        assert not config_dict.get("genesis_data_path")

    def test_config_has_valid_form(self, channel_config_factory):
        channel_config: ChannelConfig = channel_config_factory()
        channel_config.genesis_data_path = "/path/created/for/the/test.json"
        config_dict = channel_config.generate()

        keys = [key.value for key in ChannelConfigKey]
        for key in keys:
            assert key in config_dict.keys()


class TestPeerConfig:
    @pytest.mark.parametrize("channel_count", _Params.NUM_LIST)
    def test_init_by_multiple_channels(self, peer_config_factory, channel_count):
        assert peer_config_factory(channel_count=channel_count)

    @pytest.mark.parametrize("order, expected_grpc_port, expected_rest_port", [
        (0, 7100, 9000), (1, 7200, 9100), (4, 7500, 9400)
    ])
    def test_has_expected_port(self, peer_config_factory, order, expected_grpc_port, expected_rest_port):
        peer_config: PeerConfig = peer_config_factory(peer_order=order)

        assert peer_config.grpc_port == expected_grpc_port
        assert peer_config.rest_port == expected_rest_port

    def test_generate_without_channel_manage_data_path_raises_exc(self, peer_config_factory):
        peer_config: PeerConfig = peer_config_factory()
        with pytest.raises(NotFoundChannelManageDataPath):
            assert peer_config.generate()

    def test_set_genesis_data_path_in_channels(self, peer_config_factory):
        peer_config: PeerConfig = peer_config_factory()

        for channel_config in peer_config.channel_config_list:
            assert not channel_config.genesis_data_path

        expected_path = "/road/to/highway.json"
        peer_config.set_genesis_data_path_in_channels(expected_path)

        for channel_config in peer_config.channel_config_list:
            assert channel_config.genesis_data_path

    @pytest.fixture
    def peer_config_handy(self, peer_config_factory) -> PeerConfig:
        peer_config: PeerConfig = peer_config_factory()
        peer_config.set_channel_manage_data_path("/test/path.json")

        return peer_config

    def test_generate_has_valid_form(self, peer_config_handy):
        config_dict = peer_config_handy.generate()

        for key in PeerConfigKey:
            assert key.value in config_dict.keys()

    def test_write_config(self, peer_config_handy):
        assert not os.path.exists(peer_config_handy.path)

        peer_config_handy.write()
        assert os.path.exists(peer_config_handy.path)

    def test_written_file_has_valid_form(self, peer_config_handy):
        peer_config_handy.write()

        with open(peer_config_handy.path) as f:
            config_dict = json.load(f)

        for key in PeerConfigKey:
            assert key.value in config_dict.keys()


class TestGenesisData:
    def test_generate_has_valid_form(self, genesis_data_factory):
        genesis_data: GenesisData = genesis_data_factory()
        config_dict = genesis_data.generate()

        assert isinstance(config_dict, dict)
        assert "transaction_data" in config_dict
        assert "accounts" in config_dict["transaction_data"]

    def test_genesis_accounts_has_money(self, genesis_data_factory):
        genesis_data: GenesisData = genesis_data_factory()
        accounts = genesis_data.accounts

        for account in accounts:
            balance = account._balance

            assert balance.startswith("0x")
            assert int(balance, 16) > 0

    def test_write_file(self, genesis_data_factory):
        genesis_data: GenesisData = genesis_data_factory()
        assert not os.path.exists(genesis_data.path)

        genesis_data.write()
        assert os.path.exists(genesis_data.path)

    def test_written_file_has_valid_form(self, genesis_data_factory):
        genesis_data: GenesisData = genesis_data_factory()
        genesis_data.write()

        with open(genesis_data.path) as f:
            config_dict = json.load(f)

        assert isinstance(config_dict, dict)
        assert "transaction_data" in config_dict
        assert "accounts" in config_dict["transaction_data"]


class TestChannelManageData:
    def test_generate_has_valid_form(self, channel_manage_data_factory):
        channel_manage_data: ChannelManageData = channel_manage_data_factory()
        config_dict = channel_manage_data.generate()

        assert isinstance(config_dict, dict)

        for channel_name, peers_dict in config_dict.items():
            assert "peers" in peers_dict
            assert isinstance(peers_dict["peers"], list)

    def test_written_file_has_valid_form(self, channel_manage_data_factory):
        channel_manage_data: ChannelManageData = channel_manage_data_factory()
        channel_manage_data.write()

        with open(channel_manage_data.path) as f:
            config_dict = json.load(f)

        for channel_name, peers_dict in config_dict.items():
            assert "peers" in peers_dict
            assert isinstance(peers_dict["peers"], list)


class TestConfigGenerator:
    DEFAULT_CHANNEL_COUNT = 1
    DEFAULT_PEER_COUNT = 1

    def test_generate_channel_config_as_given_number(self, config_factory):
        expected_channel_config_count = 2

        config: ConfigGenerator = config_factory()
        config.generate_channel_configs(how_many=expected_channel_config_count)
        channel_config_list: List[ChannelConfig] = config._channel_config_list

        assert len(channel_config_list) == expected_channel_config_count

    def test_generate_channel_config_with_block_versions(self, config_factory):
        config: ConfigGenerator = config_factory()

        expected_height_v0_1a = 5
        expected_height_v0_3 = 10
        config.generate_channel_configs(how_many=TestConfigGenerator.DEFAULT_CHANNEL_COUNT,
                                        height_v0_1a=expected_height_v0_1a,
                                        height_v0_3=expected_height_v0_3)

        channel_config_list: List[ChannelConfig] = config._channel_config_list

        for channel_config in channel_config_list:
            config_dict = channel_config.generate()
            block_versions = config_dict[ChannelConfigKey.BLOCK_VERSIONS.value]

            assert block_versions[v0_1a.version] == expected_height_v0_1a
            assert block_versions[v0_3.version] == expected_height_v0_3

    def test_generate_peer_configs_raises_exc_if_no_channel_generated(self, config_factory):
        config: ConfigGenerator = config_factory()

        with pytest.raises(NotFoundChannelConfig):
            config.generate_peer_configs(how_many=TestConfigGenerator.DEFAULT_PEER_COUNT)

    def test_generate_peer_configs_as_given_number(self, config_factory):
        expected_channel_config_count = 4

        config: ConfigGenerator = config_factory()
        config.generate_channel_configs(how_many=TestConfigGenerator.DEFAULT_CHANNEL_COUNT)
        config.generate_peer_configs(how_many=expected_channel_config_count)

        assert len(config.peer_config_list) == expected_channel_config_count

    def test_generate_channel_manage_data_raises_exc_if_no_peer_generated(self, config_factory):
        config: ConfigGenerator = config_factory()
        config.generate_channel_configs(how_many=TestConfigGenerator.DEFAULT_CHANNEL_COUNT)

        with pytest.raises(NotFoundPeerConfig):
            config.generate_channel_manage_data()

    def test_generate_channel_manage_data(self, config_factory):
        config: ConfigGenerator = config_factory()
        config.generate_channel_configs(how_many=TestConfigGenerator.DEFAULT_CHANNEL_COUNT)
        config.generate_peer_configs(how_many=TestConfigGenerator.DEFAULT_PEER_COUNT)

        assert not config.channel_manage_data

        config.generate_channel_manage_data()
        assert config.channel_manage_data

    def test_generate_genesis_data_raises_exc_if_no_peer_generated(self, config_factory):
        config: ConfigGenerator = config_factory()
        config.generate_channel_configs(how_many=TestConfigGenerator.DEFAULT_CHANNEL_COUNT)

        with pytest.raises(NotFoundPeerConfig):
            config.generate_genesis_data()

    def test_only_first_peer_has_genesis_data_path(self, config_factory):
        config: ConfigGenerator = config_factory()
        config.generate_all(channel_count=TestConfigGenerator.DEFAULT_CHANNEL_COUNT,
                            peer_count=TestConfigGenerator.DEFAULT_PEER_COUNT)

        for peer_order, peer_config in enumerate(config.peer_config_list):
            for channel_config in peer_config.channel_config_list:
                if peer_order == 0:
                    assert channel_config.genesis_data_path
                else:
                    assert not channel_config.genesis_data_path

    def test_write_has_right_path(self, config_factory):
        config: ConfigGenerator = config_factory()
        config.generate_all(channel_count=TestConfigGenerator.DEFAULT_CHANNEL_COUNT,
                            peer_count=TestConfigGenerator.DEFAULT_PEER_COUNT)

        assert not os.path.exists(config.genesis_data.path)
        assert not os.path.exists(config.channel_manage_data.path)
        for peer_config in config.peer_config_list:
            assert not os.path.exists(peer_config.path)

        config.write()
        assert os.path.exists(config.genesis_data.path)
        assert os.path.exists(config.channel_manage_data.path)
        for peer_config in config.peer_config_list:
            assert os.path.exists(peer_config.path)


