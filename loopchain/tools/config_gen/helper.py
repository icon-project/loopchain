import json
import os
from pathlib import Path
from typing import List, Union

from loopchain.blockchain.merkle import MerkleTree
from loopchain.blockchain.types import ExternalAddress
from loopchain.tools.config_gen.const import *
from loopchain.tools.config_gen.types import Key, Keys, Config


# ----- Genesis Data
def _make_accounts(keys: Keys) -> List[Config]:
    accounts = []
    for idx, key in enumerate(keys):
        account = {
            "name": f"test_{idx}",
            "address": key.address,
            "balance": "0x2961fd42d71041700b90000"
        }
        accounts.append(account)

    return accounts


def make_genesis_data(keys: Keys, nid="0x3") -> dict:
    genesis_data = {
        "transaction_data": {
            "nid": nid,
            "accounts": _make_accounts(keys=keys),
            "message":
                "A rHizomE has no beGInning Or enD; "
                "it is alWays IN the miDDle, between tHings, interbeing, intermeZzO. "
                "ThE tree is fiLiatioN, but the rhizome is alliance, uniquelY alliance. "
                "The tree imposes the verb \"to be\" but the fabric of the rhizome is the conJUNction, "
                "\"AnD ... and ...and...\"THis conJunction carriEs enouGh force to shaKe and uproot the verb \"to be.\" "
                "Where are You goIng? Where are you coMing from? What are you heading for? "
                "These are totally useless questions.\n\n"
                "- Mille Plateaux, Gilles Deleuze & Felix Guattari\n\n\""
                "Hyperconnect the world\""
        }
    }

    return genesis_data


# ----- Channels
def make_crep_root_hash(keys: Keys) -> str:
    reps = [ExternalAddress.fromhex(key.address).extend() for key in keys]

    mktree = MerkleTree()
    mktree.add_leaf(reps, do_hash=True)
    mktree.make_tree()

    return "0x" + mktree.get_merkle_root().hex()


def make_channel_config(crep_root_hash: str, radiostations: list = None, **kwargs) -> Config:
    channel_config = {
        "block_versions": {
            "0.1a": 0,
            "0.3": 1
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
        "radiostations": radiostations,
        "crep_root_hash": crep_root_hash
    }

    for key, value in kwargs.items():
        channel_config[key] = value

    return channel_config


# ----- Peers
def make_peer_config(channels_config: Config, port_peer: int, key: Key, **kwargs) -> Config:
    peer_config = dict()
    peer_config["CHANNEL_OPTION"] = channels_config
    peer_config["PRIVATE_PATH"] = str(key.path)
    peer_config["PRIVATE_PASSWORD"] = key.password
    peer_config["RUN_ICON_IN_LAUNCHER"] = True
    peer_config["PORT_PEER"] = port_peer

    for key, value in kwargs.items():
        peer_config[key] = value

    return peer_config


# ----- Channel Manage Data
def _make_peers_in_channel_manage_data(keys: Keys) -> List[Config]:
    peers = []

    for order, key in enumerate(keys):
        grpc_port = make_port_by_order(order, start_port=PORT_PEER)
        peer = {
            "id": key.address,
            "peer_target": f"[local_ip]:{grpc_port}",
            "order": order + 1
        }
        peers.append(peer)

    return peers


def make_channel_manage_data(channel_names: list, keys: Keys) -> Config:
    channel_manage_data = {}
    for channel_name in channel_names:
        channel_manage_data[channel_name] = {
            "peers": _make_peers_in_channel_manage_data(keys=keys)
        }

    return channel_manage_data


# ----- Other helper funcs
def make_port_by_order(order: int, start_port: int) -> int:
    return start_port + order * PORT_DIFF_BETWEEN_PEERS


def make_radiostations_for_local(n: int) -> list:
    """Make radiostations for local test."""
    return [f"[local_ip]:{PORT_PEER_FOR_REST + (i * PORT_DIFF_BETWEEN_PEERS)}"
            for i in range(n)]


def check_param_exist(attr_name: str):
    """Decorator on class methods that checks that its instance attr exists."""
    def _check(func):
        def __check(self, *args, **kwargs):
            if getattr(self, attr_name) is None:
                raise RuntimeError(f"build_{attr_name} first")
            else:
                return func(self, *args, **kwargs)
        return __check
    return _check


def dict_write(path: Union[Path, str], dict_obj: dict):
    """Write dict value to path."""
    if os.path.exists(path):
        raise FileExistsError(f"{path} already exists.")

    with open(path, "w", encoding="utf-8") as f:
        s = json.dumps(dict_obj, indent=2)
        f.write(s)
