import copy
import json
import os
from typing import List, Optional, Dict

from iconsdk.wallet.wallet import KeyWallet

from loopchain.blockchain.blocks import v0_1a
from loopchain.blockchain.blocks import v0_3
from testcase.integration.configure.config_key import ChannelConfigKey, PeerConfigKey
from testcase.integration.configure.exceptions import (
    NotFoundChannelConfig, NotFoundChannelManageDataPath, NotFoundBlockVersions, NotFoundPeerConfig
)


class Account:
    """Represent Rep account and its wallet.

    Used in generating GenesisData.
    """

    def __init__(self, root_path, name, password="password", balance="0x2961fd42d71041700b90000"):
        self._name = name
        self._path = os.path.join(root_path, f"keystore_{self._name}.json")

        self._password = password
        self._balance = balance

        KeyWallet.create().store(self._path, self._password)
        self._wallet: KeyWallet = KeyWallet.load(self._path, self._password)

    @property
    def path(self):
        return self._path

    @property
    def name(self):
        return self._name

    @property
    def password(self):
        return self._password

    @property
    def wallet(self) -> KeyWallet:
        return self._wallet

    @property
    def address(self):
        return self._wallet.address

    def generate(self) -> dict:
        return {
            "name": self._name,
            "address": self.address,
            "balance": self._balance
        }

    def write(self):
        with open(self._path, "w") as f:
            json.dump(self.generate(), f)


class ChannelConfig:
    """Represent Channel Config."""
    def __init__(self, name="icon_dex"):
        # Required
        self._name: str = name

        # Generated
        self._block_versions: Dict[str, int] = {}
        self._genesis_data_path: str = ""

        # Optional
        self._load_cert = False
        self._consensus_cert_use = False
        self._tx_cert_use = False
        self._key_load_type = 0

    @property
    def name(self):
        return self._name

    @property
    def genesis_data_path(self) -> str:
        return self._genesis_data_path

    @genesis_data_path.setter
    def genesis_data_path(self, path):
        self._genesis_data_path = path

    def set_block_version_heights(self, height_v0_1a: int, height_v0_3: int):
        block_version = {}

        if height_v0_1a >= 0:
            block_version[v0_1a.version] = height_v0_1a
        if height_v0_3 >= 0:
            block_version[v0_3.version] = height_v0_3

        self._block_versions = block_version

    def generate(self) -> dict:
        if not self._block_versions:
            raise NotFoundBlockVersions("Set block version height first!")

        channel_config: dict = {
            ChannelConfigKey.BLOCK_VERSIONS.value: self._block_versions,
            ChannelConfigKey.HASH_VERSIONS.value: {
                "genesis": 1,
                "0x2": 1,
                "0x3": 1
            },
            ChannelConfigKey.LOAD_CERT.value: self._load_cert,
            ChannelConfigKey.CONSENSUS_CERT_USE.value: self._consensus_cert_use,
            ChannelConfigKey.TX_CERT_USE.value: self._tx_cert_use,
            ChannelConfigKey.KEY_LOAD_TYPE.value: self._key_load_type,
            ChannelConfigKey.RADIOSTATIONS.value: [
                "[local_ip]:9000",
                "[local_ip]:9100",
                "[local_ip]:9200",
                "[local_ip]:9300",
                "[local_ip]:9400",
                "[local_ip]:9500",
                "[local_ip]:9600",
                "[local_ip]:9700",
            ]
        }

        if self.genesis_data_path:
            channel_config[ChannelConfigKey.GENESIS_DATA_PATH.value] = self._genesis_data_path

        return channel_config


class PeerConfig:
    """Represent Peer Config.

    It can contain multiple Channel Configs.
    """
    STORAGE_FOLDER_NAME = ".storage"
    PORT_DIFF = 1900
    FIRST_GRPC_PORT = 7100

    def __init__(self, root_path, peer_order: int, channel_config_list: List[ChannelConfig]):
        # Required
        self._peer_order: int = peer_order
        self._path = os.path.join(root_path, f"test_{self._peer_order}_conf.json")

        # Generated
        self._account = Account(root_path, f"atheist_{self._peer_order}")
        self._channel_config_list: List[ChannelConfig] = channel_config_list
        self._channel_manage_data_path = None
        self._default_storage_path = os.path.join(root_path, PeerConfig.STORAGE_FOLDER_NAME)

        # Optional
        self._loopchain_develop_log_level = "INFO"
        self._run_icon_in_launcher = True
        self._allow_make_empty_block = True

    @property
    def path(self):
        return self._path

    @property
    def grpc_port(self):
        return PeerConfig.FIRST_GRPC_PORT + (self._peer_order * 100)

    @property
    def rest_port(self):
        return self.grpc_port + PeerConfig.PORT_DIFF

    @property
    def account(self):
        return self._account

    @property
    def channel_config_list(self) -> List[ChannelConfig]:
        return self._channel_config_list

    @property
    def channel_name_list(self) -> List[str]:
        return [channel_config.name for channel_config in self._channel_config_list]

    def set_channel_manage_data_path(self, path):
        self._channel_manage_data_path = path

    def set_genesis_data_path_in_channels(self, path):
        """Set genesis path to all ChannelConfigs in this peer."""
        for channel_config in self._channel_config_list:
            channel_config.genesis_data_path = path

    def generate(self) -> dict:
        if not self._channel_manage_data_path:
            raise NotFoundChannelManageDataPath()

        return {
            PeerConfigKey.LOOPCHAIN_DEFAULT_CHANNEL.value: self.channel_name_list[0],
            PeerConfigKey.CHANNEL_OPTION.value: self._generate_channel_configs(),
            PeerConfigKey.PRIVATE_PATH.value: self._account.path,
            PeerConfigKey.PRIVATE_PASSWORD.value: self._account.password,
            PeerConfigKey.RUN_ICON_IN_LAUNCHER.value: self._run_icon_in_launcher,
            PeerConfigKey.ALLOW_MAKE_EMPTY_BLOCK.value: self._allow_make_empty_block,
            PeerConfigKey.PORT_PEER.value: self.grpc_port,
            PeerConfigKey.PEER_ORDER.value: self._peer_order,
            PeerConfigKey.PEER_ID.value: self._account.address,
            PeerConfigKey.LOOPCHAIN_DEVELOP_LOG_LEVEL.value: self._loopchain_develop_log_level,
            PeerConfigKey.DEFAULT_STORAGE_PATH.value: self._default_storage_path,
            PeerConfigKey.CHANNEL_MANAGE_DATA_PATH.value: self._channel_manage_data_path
        }

    def _generate_channel_configs(self):
        return {channel_config.name: channel_config.generate()
                for channel_config in self._channel_config_list}

    def write(self):
        with open(self._path, "w") as f:
            json.dump(self.generate(), f)


class GenesisData:
    def __init__(self, root_path, accounts, nid="0x3"):
        self._path = os.path.join(root_path, "genesis_test.json")
        self._data: dict = {}
        self._nid: str = nid
        self._accounts: List[Account] = accounts

    @property
    def path(self):
        return self._path

    @property
    def accounts(self) -> List[Account]:
        return self._accounts

    def generate(self) -> dict:
        return {
            "transaction_data": {
                "nid": self._nid,
                "accounts": [account.generate() for account in self._accounts],
                "message": "A rHizomE has no beGInning Or enD; it is alWays IN the miDDle, between tHings, interbeing, intermeZzO. ThE tree is fiLiatioN, but the rhizome is alliance, uniquelY alliance. The tree imposes the verb \"to be\" but the fabric of the rhizome is the conJUNction, \"AnD ... and ...and...\"THis conJunction carriEs enouGh force to shaKe and uproot the verb \"to be.\" Where are You goIng? Where are you coMing from? What are you heading for? These are totally useless questions.\n\n- Mille Plateaux, Gilles Deleuze & Felix Guattari\n\n\"Hyperconnect the world\""
            }
        }

    def write(self):
        with open(self._path, "w") as f:
            json.dump(self.generate(), f)


class ChannelManageData:
    def __init__(self, root_path, peer_config_list: List[PeerConfig]):
        self._path = os.path.join(root_path, "channel_manage_data.json")
        self._data = {}
        self._peer_config_list: List[PeerConfig] = peer_config_list

    @property
    def path(self):
        return self._path

    def generate(self):
        channel_manage_data = {}
        peers = []

        for peer_order, peer_config in enumerate(self._peer_config_list, start=1):
            peer_config.set_channel_manage_data_path(self._path)
            peers.append({
                "id": peer_config.account.address,
                "peer_target": f"[local_ip]:{peer_config.grpc_port}",
                "order": peer_order
            })

        for channel_name in self._peer_config_list[0].channel_name_list:
            channel_manage_data[channel_name] = {"peers": peers}

        self._data = channel_manage_data

        return self._data

    def write(self):
        with open(self._path, "w") as f:
            json.dump(self.generate(), f)


class ConfigGenerator:
    def __init__(self, root_path):
        self._root_path = root_path

        self._peer_config_list: List[PeerConfig] = []
        self._channel_config_list: List[ChannelConfig] = []
        self._genesis_data: Optional[GenesisData] = None
        self._channel_manage_data: Optional[ChannelManageData] = None

    @property
    def genesis_data(self) -> GenesisData:
        return self._genesis_data

    @property
    def channel_manage_data(self):
        return self._channel_manage_data

    @property
    def peer_config_list(self):
        return self._peer_config_list

    def generate_all(self, channel_count: int, peer_count: int):
        self.generate_channel_configs(how_many=channel_count)
        self.generate_peer_configs(how_many=peer_count)
        self.generate_channel_manage_data()
        self.generate_genesis_data()

    def generate_channel_configs(self, how_many: int, height_v0_1a: int = 0, height_v0_3: int = 1):
        self._channel_config_list = []

        for channel_num in range(how_many):
            channel_config: ChannelConfig = ChannelConfig(f"channel_{channel_num}")
            channel_config.set_block_version_heights(height_v0_1a=height_v0_1a, height_v0_3=height_v0_3)
            self._channel_config_list.append(channel_config)

    def generate_peer_configs(self, how_many: int):
        if not self._channel_config_list:
            raise NotFoundChannelConfig("There's no ChannelConfig. Generate First!")

        self._peer_config_list = []

        for peer_order in range(how_many):
            peer_config = self._generate_single_peer_config(peer_order)
            self._peer_config_list.append(peer_config)

    def _generate_single_peer_config(self, peer_order):
        channel_configs: List[ChannelConfig] = copy.deepcopy(self._channel_config_list)
        peer_config: PeerConfig = PeerConfig(root_path=self._root_path,
                                             peer_order=peer_order,
                                             channel_config_list=channel_configs)

        return peer_config

    def generate_channel_manage_data(self):
        if not self._peer_config_list:
            raise NotFoundPeerConfig("There's no PeerConfig. Generate First!")

        self._channel_manage_data = ChannelManageData(self._root_path, peer_config_list=self._peer_config_list)

    def generate_genesis_data(self):
        if not self._peer_config_list:
            raise NotFoundPeerConfig("There's no PeerConfig. Generate First!")

        accounts = [peer_config.account for peer_config in self._peer_config_list]

        self._genesis_data = GenesisData(self._root_path, accounts=accounts)
        self._set_genesis_data_path_in_leader_peer()

    def _set_genesis_data_path_in_leader_peer(self):
        leader_peer_config = self._peer_config_list[0]
        for channel_config in leader_peer_config.channel_config_list:
            channel_config.genesis_data_path = self._genesis_data.path

    def write(self):
        self._genesis_data.write()
        self._channel_manage_data.write()

        for peer_config in self._peer_config_list:
            peer_config.write()
