import functools
from typing import List, Callable

import pytest

from testcase.integration.configure.config_generator import (
    Account, ChannelConfig, PeerConfig, GenesisData, ChannelManageData
)


@pytest.fixture
def account_factory(tmp_path):
    def _account(root_path, name="test_key", password="password", balance="0x9999999"):
        account = Account(root_path=root_path, name=name, password=password, balance=balance)

        return account

    return functools.partial(_account, root_path=tmp_path)


@pytest.fixture
def channel_config_factory() -> Callable[..., ChannelConfig]:
    def _channel_config(channel_name="icon_dex", height_v0_1a: int = 0, height_v0_3: int = 1) -> ChannelConfig:
        channel_config: ChannelConfig = ChannelConfig(channel_name)
        channel_config.set_block_version_heights(height_v0_1a=height_v0_1a, height_v0_3=height_v0_3)

        return channel_config

    return _channel_config


@pytest.fixture
def multiple_channel_config_factory(channel_config_factory) -> Callable[..., List[PeerConfig]]:
    def _multiple_channel_config_factory(_channel_config_factory, channel_count: int) -> List[PeerConfig]:
        channel_config_list = [_channel_config_factory(channel_name=f"channel_{channel_num}")
                               for channel_num in range(channel_count)]

        return channel_config_list

    return functools.partial(_multiple_channel_config_factory, _channel_config_factory=channel_config_factory)


@pytest.fixture
def peer_config_factory(tmp_path, multiple_channel_config_factory) -> Callable[..., PeerConfig]:
    def _peer_config(root_path, _channel_config_factory, peer_order: int = 0, channel_count: int = 2):
        channel_config_list = _channel_config_factory(channel_count=channel_count)
        peer_config = PeerConfig(root_path,
                                 peer_order=peer_order,
                                 channel_config_list=channel_config_list)
        return peer_config

    return functools.partial(_peer_config, root_path=tmp_path, _channel_config_factory=multiple_channel_config_factory)


@pytest.fixture
def multiple_peer_config_factory(peer_config_factory) -> Callable[..., List[PeerConfig]]:
    def _multiple_channel_config_factory(_peer_config_factory, peer_count: int) -> List[PeerConfig]:
        peer_config_list = [_peer_config_factory(peer_order=peer_order)
                            for peer_order in range(peer_count)]

        return peer_config_list

    return functools.partial(_multiple_channel_config_factory, _peer_config_factory=peer_config_factory)


@pytest.fixture
def channel_manage_data_factory(tmp_path, multiple_peer_config_factory) -> Callable[..., ChannelManageData]:
    def _channel_manage_data(root_path, _peer_config_factory, peer_count: int = 4) -> ChannelManageData:
        peer_config_list = _peer_config_factory(peer_count=peer_count)
        channel_manage_data = ChannelManageData(root_path, peer_config_list=peer_config_list)

        return channel_manage_data

    return functools.partial(_channel_manage_data, root_path=tmp_path, _peer_config_factory=multiple_peer_config_factory)


@pytest.fixture
def genesis_data_factory(tmp_path, multiple_peer_config_factory) -> Callable[..., GenesisData]:
    def _genesis_data(root_path, _peer_config_factory) -> GenesisData:
        peer_config_list: List[PeerConfig] = _peer_config_factory(peer_count=4)
        accounts = [peer_config.account for peer_config in peer_config_list]
        genesis_data = GenesisData(root_path=root_path, accounts=accounts)

        return genesis_data

    return functools.partial(_genesis_data, root_path=tmp_path, _peer_config_factory=multiple_peer_config_factory)
