import functools
from typing import Callable

import pytest

from loopchain.tools.config_gen.config_gen import ConfigGenerator

DEFAULT_KEY_PASSWORD = "pAsSwOrD"
DEFAULT_TOTAL_REPS = 4
DEFAULT_MAIN_REPS = 2
DEFAULT_CHANNEL_NAMES = ("icon_dex", "dex_icon")


@pytest.fixture
def config_gen_factory(tmp_path) -> Callable[..., ConfigGenerator]:
    def _config_gen_factory(_config_root_path, password=DEFAULT_KEY_PASSWORD,
                            total_reps_count=DEFAULT_TOTAL_REPS, main_reps_count=DEFAULT_MAIN_REPS,
                            channel_names=DEFAULT_CHANNEL_NAMES):
        return ConfigGenerator(
            config_root=_config_root_path,
            key_password=password,
            total_reps_count=total_reps_count,
            main_reps_count=main_reps_count,
            channel_names=channel_names
        )

    config_root_path = tmp_path / "config_root"
    return functools.partial(_config_gen_factory, _config_root_path=config_root_path)


class TestConfigGenerator:
    def test_generate_all_stages(self, config_gen_factory):
        config_gen = config_gen_factory()

        config_gen.build()
        config_gen.write()

    def test_write_failed_when_config_already_exists(self, config_gen_factory):
        config_gen = config_gen_factory()
        config_gen.build()
        config_gen.write()

        with pytest.raises(FileExistsError):
            config_gen.write()


class TestConfigGeneratorKeys:
    def test_build_all_reps_key(self, config_gen_factory):
        expected_total_reps = 8
        config_gen = config_gen_factory(total_reps_count=expected_total_reps)
        assert not config_gen.keys

        config_gen.build_keys()
        assert config_gen.keys
        assert expected_total_reps == len(config_gen.keys)

    def test_build_returns_its_data_if_exists(self, config_gen_factory):
        expected_data = {"this": "is_test"}

        config_gen = config_gen_factory()
        config_gen.keys = expected_data

        config_gen.build_keys()

        assert config_gen.keys == expected_data

    def test_write_at_valid_path(self, config_gen_factory):
        config_gen = config_gen_factory()

        config_gen.build_keys()
        for key in config_gen.keys:
            assert not key.path.exists()

        config_gen.write_keys()
        for key in config_gen.keys:
            assert key.path.exists()


class TestConfigGeneratorGenesisData:
    def test_build_failed_if_key_is_not_built(self, config_gen_factory):
        config_gen = config_gen_factory()
        assert not config_gen.genesis_data

        with pytest.raises(RuntimeError, match="build_keys first"):
            config_gen.build_genesis_data()

    def test_build_genesis_data(self, config_gen_factory):
        config_gen = config_gen_factory()
        assert not config_gen.genesis_data

        config_gen.build_keys()
        config_gen.build_genesis_data()
        assert isinstance(config_gen.genesis_data, dict)

    def test_build_returns_its_data_if_exists(self, config_gen_factory):
        expected_data = {"this": "is_test"}

        config_gen = config_gen_factory()
        config_gen.genesis_data = expected_data

        config_gen.build_keys()
        config_gen.build_genesis_data()

        assert config_gen.genesis_data == expected_data

    def test_write_at_valid_path(self, config_gen_factory):
        config_gen = config_gen_factory()

        config_gen.build_keys()
        config_gen.build_genesis_data()
        path = config_gen.write_genesis_data()

        assert path.exists()


class TestConfigGeneratorPeerConfigs:
    def test_build_failed_if_key_is_not_built(self, config_gen_factory):
        config_gen = config_gen_factory()

        with pytest.raises(RuntimeError, match="build_keys first"):
            config_gen.build_peer_configs()

    def test_build_peer_configs(self, config_gen_factory):
        config_gen = config_gen_factory()
        assert not config_gen.peer_configs

        config_gen.build_keys()
        config_gen.build_channels_config()
        config_gen.build_peer_configs()
        assert config_gen.peer_configs

    def test_build_returns_its_data_if_exists(self, config_gen_factory):
        expected_data = {"this": "is_test"}

        config_gen = config_gen_factory()
        config_gen.peer_configs = expected_data

        config_gen.build_keys()
        config_gen.build_channels_config()
        config_gen.build_peer_configs()

        assert config_gen.peer_configs == expected_data

    def test_build_and_only_first_peer_has_genesis_path(self, config_gen_factory):
        def is_genesis_in_peer_config(peer_conf):
            for channel_name in peer_conf["CHANNEL_OPTION"]:
                return "genesis_data_path" in peer_conf["CHANNEL_OPTION"][channel_name]

        config_gen = config_gen_factory()
        config_gen.build_keys()
        config_gen.build_channels_config()
        config_gen.build_peer_configs()

        first_peer_config = config_gen.peer_configs[0]
        assert is_genesis_in_peer_config(first_peer_config)

        rest_of_peer_configs = config_gen.peer_configs[1:]
        for peer_config in rest_of_peer_configs:
            assert not is_genesis_in_peer_config(peer_config)

    def test_write_at_valid_path(self, config_gen_factory):
        config_gen = config_gen_factory()

        config_gen.build_keys()
        config_gen.build_channels_config()
        config_gen.build_peer_configs()
        peer_config_paths = config_gen.write_peer_configs()

        for path in peer_config_paths:
            assert path.exists()


class TestConfigGeneratorChannelManageData:
    def test_build_failed_if_key_is_not_built(self, config_gen_factory):
        config_gen = config_gen_factory()

        with pytest.raises(RuntimeError, match="build_keys first"):
            config_gen.build_channel_manage_data()

    def test_build_channel_manage_data(self, config_gen_factory):
        config_gen = config_gen_factory()
        assert not config_gen.channel_manage_data

        config_gen.build_keys()
        config_gen.build_channel_manage_data()
        assert config_gen.channel_manage_data

    def test_build_returns_its_data_if_exists(self, config_gen_factory):
        expected_data = {"this": "is_test"}

        config_gen = config_gen_factory()
        config_gen.channel_manage_data = expected_data

        config_gen.build_keys()
        config_gen.build_channel_manage_data()

        assert config_gen.channel_manage_data == expected_data

    def test_build_and_all_peers_included(self, config_gen_factory):
        total_reps_count = 8
        main_reps_count = 4

        config_gen = config_gen_factory(total_reps_count=total_reps_count, main_reps_count=main_reps_count)
        config_gen.build_keys()
        channel_manage_data = config_gen.build_channel_manage_data()

        for channel_name in channel_manage_data.keys():
            assert len(channel_manage_data[channel_name]["peers"]) == total_reps_count

    def test_write_at_valid_path(self, config_gen_factory):
        config_gen = config_gen_factory()

        config_gen.build_keys()
        config_gen.build_channel_manage_data()
        path = config_gen.write_channel_manage_data()

        assert path.exists()

    def test_write_and_only_main_reps_included(self, config_gen_factory):
        total_reps_count = 8
        main_reps_count = 4

        config_gen = config_gen_factory(total_reps_count=total_reps_count, main_reps_count=main_reps_count)
        config_gen.build_keys()
        config_gen.build_channel_manage_data()
        path = str(config_gen.write_channel_manage_data())

        with open(path, encoding="utf-8") as f:
            import json
            channel_manage_data = json.load(f)

        for channel_name in channel_manage_data.keys():
            assert len(channel_manage_data[channel_name]["peers"]) == main_reps_count



