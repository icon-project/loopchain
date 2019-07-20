import itertools
import json
from typing import Tuple
import os
from functools import partial

import pytest
from iconsdk.wallet.wallet import KeyWallet
from xprocess import ProcessStarter

port_channel_list = []


def pytest_addoption(parser):
    """Set args for tests

    Options below can be used at `--opt`
        >> pytest testcat/integration [--opt]
        ...
    """
    parser.addoption("--peer-count", action="store", default=4, help="Number of peer to be tested")
    parser.addoption("--peer-type", action="store", default="peer", help="Type of peer. ([peer|citizen])")
    parser.addoption("--channel-count", action="store", default=2, help="Number of channel to set in each peer.\n"
                                                                        "Each will be named as 'channel_[num]'.\n"
                                                                        "Use this option to test multi-channel.\n")


def pytest_configure(config):
    """Make parameter list reuse in integration tests"""
    peer_count = int(config.getoption("--peer-count"))
    channel_count = int(config.getoption("--channel-count"))

    for peer_order in range(peer_count):
        port = 9000 + (peer_order * 100)
        for channel_num in range(channel_count):
            port_channel_list.append([port, f"channel_{channel_num}"])

    print("list made: ", port_channel_list)


def _get_channel_setting() -> dict:
    """Default config format for each channel

    :return dict channel_setting : Default config format for each channel
    """
    channel_setting = {
        "block_versions": {
            "0.1a": 0
        },
        "hash_versions": {
            "genesis": 1,
            "0x2": 1,
            "0x3": 1
        },
        "load_cert": False,
        "consensus_cert_use": False,
        "tx_cert_use": False,
        "key_load_type": 0,
    }

    return channel_setting


def generate_addr(wallet_key_path: str, password: str = "password") -> str:
    """Generate address from given wallet path and password

    :param str wallet_key_path : Desired path of wallet key file
    :param str password : Desired password of wallet
    :return str account_addr: Account address of wallet
    """
    wallet = KeyWallet.create()
    wallet.store(wallet_key_path, password)
    account_addr = KeyWallet.load(wallet_key_path, password).get_address()

    return account_addr


def generate_channel_manage_data(channel_manage_data_path: str, config_path_list: list):
    """Generate channel_manage_data.json at given path

    :param str channel_manage_data_path: Desired path of channel_manage_data.json
    :param list config_path_list: Peer information list to be contained to the json file
    """
    channel_manage_data = {}
    peers = []

    for config_path in config_path_list:
        with open(config_path) as f:
            each_config = json.load(f)

        for channel_name in each_config["CHANNEL_OPTION"]:
            channel_manage_data[channel_name] = {
                "score_package": "score/icx",
            }

        each_peer = {
            "id": each_config["PEER_ID"],
            "peer_target": f"[local_ip]:{each_config['PORT_PEER']}",
            "order": each_config["PEER_ORDER"]
        }
        peers.append(each_peer)

    for channel_name in channel_manage_data:
        channel_manage_data[channel_name]["peers"] = peers

    with open(channel_manage_data_path, "w") as f:
        json.dump(channel_manage_data, f)


def generate_genesis_file(genesis_path: str, accounts: list):
    """Generate genesis file at given path

    Makes genesis block tx which is to be contained in genesis block

    :param str genesis_path : Desired path of genesis file
    :param list accounts : Account list to be contained to genesis tx. Sample schema is below.
        accounts = [
            {
                "name": "treasury",
                "address": "hx1000000000000000000000000000000000000000",
                "balance": "0x1111"
            },
            ...
        ]
    """
    genesis_data = {
        "transaction_data": {
            "nid": "0x3",
            "accounts": accounts,
            "message":
                "A rHizomE has no beGInning Or enD; "
                "it is alWays IN the miDDle, between tHings, interbeing, intermeZzO. ThE tree is fiLiatioN, "
                "but the rhizome is alliance, uniquelY alliance. "
                "The tree imposes the verb \"to be\" but the fabric of the rhizome is the conJUNction, "
                "\"AnD ... and ...and...\""
                "THis conJunction carriEs enouGh force to shaKe and uproot the verb \"to be.\" "
                "Where are You goIng? Where are you coMing from? What are you heading for? "
                "These are totally useless questions.\n\n- 'Mille Plateaux', Gilles Deleuze & Felix Guattari\n\n\""
                "Hyperconnect the world\""
        }
    }

    with open(genesis_path, "w") as f:
        json.dump(genesis_data, f)


def get_peer_info(conf_path_list: list, order: int = 0) -> dict:
    """Get peer information

    :param list conf_path_list: List of peer config paths
    :param int order: Peer order in list to extract its info
    :return dict peer_info: Peer information
    """
    target_peer_conf_path = conf_path_list[order]

    with open(target_peer_conf_path) as f:
        peer_info = json.load(f)

    return peer_info


def get_genesis_data(conf_path_list: list) -> dict:
    """Get genesis data from first peer's information

    :param list conf_path_list: List of peer config paths
    :return dict loaded_genesis_data: Genesis data
    """
    if not conf_path_list:
        raise RuntimeError()

    peer_info = get_peer_info(conf_path_list=conf_path_list, order=0)
    genesis_path = peer_info["CHANNEL_OPTION"]["channel_0"]["genesis_data_path"]

    with open(genesis_path) as f:
        loaded_genesis_data = json.load(f)

    return loaded_genesis_data


def _generate_peer_conf_path_list(temporary_path,
                                  peer_count: int,
                                  channel_list: list,
                                  wallet_password: str = "password") -> Tuple[list, str]:
    """Generate config for one peer

    It must be used as a wrapped function, due to the random-generated config path.
    TODO: This function would be out-of-dated, due to features related to remove channel_manage_data.json

    :param fixture temporary_path: Pytest built-in fixture to make temporary config path
    :param int peer_count: Desired number to create peer configs
    :param str wallet_password: Password of wallet
    :param list channel_list: Iterable contains channel names. Those channels will be inserted to each peer' config.

    :returns:
        - peer_conf_path_list (:py:class:`list`) - List of configure file paths
        - channel_manage_data_path (:py:class:`str`): Path of channel manage data
    """
    accounts_in_genesis = [
        {
            "name": "god",
            "address": "hx0000000000000000000000000000000000000000",
            "balance": "0x2961ffa20dd47f5c4700000"
        },
        {
            "name": "treasury",
            "address": "hx1000000000000000000000000000000000000000",
            "balance": "0x0"
        }
    ]
    genesis_path = os.path.join(temporary_path, "genesis_test.json")
    chann_manage_path = os.path.join(temporary_path, "channel_manage_data.json")

    peer_conf_path_list = []

    for peer_order in range(peer_count):
        # MAKE KEY FILES
        wallet_key_path = os.path.join(temporary_path, f"keystore_{peer_order}.json")
        account_addr = generate_addr(wallet_key_path, password="password")

        # MAKE GENESIS FILE
        accounts_in_genesis.append({
            "name": f"atheist_{peer_order}",
            "address": account_addr,
            "balance": "0x2961ffa20dd47f5c4700000" if peer_order == 0 else "0x0"
        })

        # PEER CONFIG SETTING
        channel_setting: dict = _get_channel_setting()
        if peer_order == 0:
            channel_setting["genesis_data_path"] = genesis_path

        peer_config = {
            "LOOPCHAIN_DEFAULT_CHANNEL": channel_list[0],
            "CHANNEL_OPTION": {channel_name: channel_setting for channel_name in channel_list},
            "PRIVATE_PATH": wallet_key_path,
            "PRIVATE_PASSWORD": wallet_password,
            "RUN_ICON_IN_LAUNCHER": True,
            "ALLOW_MAKE_EMPTY_BLOCK": False,
            "PORT_PEER": 7100 + (peer_order * 100),
            "PEER_ORDER": peer_order + 1,
            "PEER_ID": account_addr,
            "LOOPCHAIN_DEVELOP_LOG_LEVEL": "INFO",
            "DEFAULT_STORAGE_PATH": os.path.join(temporary_path, ".storage_integration_test"),
            "CHANNEL_MANAGE_DATA_PATH": chann_manage_path
        }

        # WRITE EACH PEER CONFIG
        config_path = os.path.join(temporary_path, f"conf_{peer_order}.json")
        with open(config_path, "w") as f:
            json.dump(peer_config, f)
        peer_conf_path_list.append(config_path)

    generate_genesis_file(genesis_path=genesis_path, accounts=accounts_in_genesis)
    generate_channel_manage_data(channel_manage_data_path=chann_manage_path, config_path_list=peer_conf_path_list)

    return peer_conf_path_list, chann_manage_path


@pytest.fixture
def generate_peer_conf_path_list(tmp_path_factory):
    """Generate list of peer config file paths

    This is for 'tests_for_fixtures', which tests fixtures of integration test.
    Whenever it called, it creates brand-new config path list.
    """
    tmp_path = tmp_path_factory.mktemp("function_scope_test")
    return partial(_generate_peer_conf_path_list, temporary_path=tmp_path)


@pytest.fixture(scope="class")
def generate_peer_conf_path_list_extended(tmp_path_factory):
    """Generate list of peer config file paths

    Aimed for long-running processes in test,
    this fixture is activated when the scope is valid and, and processes are terminated when the scope is end.
    """
    tmp_path = tmp_path_factory.mktemp("widen_scope_test")
    return partial(_generate_peer_conf_path_list, temporary_path=tmp_path)


class Loopchain(ProcessStarter):
    """Loopchain process starter

    When the number of stdout line reaches to the `end_line` with no `pattern` matched,
    Loopchain process assumes that the process has failed to run.

    - args      : Cmd args to execute process
    - pattern   : Expected regex pattern to be found from stdout.
        If the pattern is found, It assumes that the process is successfully started
    - end_line  : Deadline of stdout pattern matching.
    """
    args = None
    pattern = None
    end_line: int = None

    def filter_lines(self, lines):
        return itertools.islice(lines, Loopchain.end_line)
