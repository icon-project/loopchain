import copy
from pathlib import Path
from typing import List, Iterable

from loopchain.tools.config_gen.helper import (
    check_param_exist, dict_write, make_port_by_order, make_radiostations_for_local,
    make_crep_root_hash, make_genesis_data, make_channel_config, make_peer_config, make_channel_manage_data
)
from loopchain.tools.config_gen.types import Key, Keys, Config


class ConfigGenerator:
    def __init__(self, config_root: Path, channel_names: List[str], total_reps_count: int,
                 main_reps_count: int = None,
                 key_password: str = None, key_root: Path = None):
        # Required Inputs
        self._config_root: Path = config_root.expanduser().resolve()
        self._total_reps_count: int = total_reps_count
        self._channel_names: List[str] = channel_names

        # Generated Outputs
        self.keys: Keys = None
        self.genesis_data: Config = None
        self.channels_config: Config = None
        self.peer_configs: List[Config] = None
        self.channel_manage_data: Config = None

        # Optional
        self.main_reps_count: int = main_reps_count or total_reps_count
        self.key_root: Path = key_root or self._config_root / "keys"
        self.key_password: str = key_password or "password"

    def build(self):
        self.build_keys()
        self.build_genesis_data()
        self.build_channels_config()
        self.build_peer_configs()
        self.build_channel_manage_data()

        return self

    def build_keys(self) -> Keys:
        if self.keys:
            return self.keys

        keys = []
        for i in range(self._total_reps_count):
            key_path = self.key_root / f"my_keystore_{i}.json"
            key = Key(path=key_path, password=self.key_password)
            keys.append(key)

        self.keys = keys

        return self.keys

    @check_param_exist("keys")
    def build_genesis_data(self) -> Config:
        if not self.genesis_data:
            self.genesis_data = make_genesis_data(self.keys)

        return self.genesis_data

    @check_param_exist("keys")
    def build_channels_config(self, **kwargs) -> Config:
        crep_root_hash = make_crep_root_hash(keys=self.keys)
        radiostations = kwargs.pop("radiostations", None) or make_radiostations_for_local(n=self.main_reps_count)

        channels_config = dict()
        for channel_name in self._channel_names:
            channel_config = make_channel_config(
                crep_root_hash=crep_root_hash,
                radiostations=radiostations,
                **kwargs)
            channels_config[channel_name] = channel_config

        self.channels_config = channels_config

        return channels_config

    @check_param_exist("keys")
    @check_param_exist("channels_config")
    def build_peer_configs(self, **kwargs) -> List[Config]:
        if self.peer_configs:
            return self.peer_configs

        peer_configs = []
        for idx, key in enumerate(self.keys):
            rest_port = make_port_by_order(idx, start_port=7100)
            peer_config = make_peer_config(channels_config=self.channels_config, port_peer=rest_port, key=key, **kwargs)
            peer_configs.append(peer_config)

        peer_configs[0] = self._insert_genesis_path_to_first_channel_of_peer(peer_configs[0])
        self.peer_configs = peer_configs

        return peer_configs

    def _insert_genesis_path_to_first_channel_of_peer(self, peer_config: Config) -> Config:
        peer_config = copy.deepcopy(peer_config)

        channels_config: Config = peer_config["CHANNEL_OPTION"]
        for channel_name in channels_config.keys():
            channels_config[channel_name]["genesis_data_path"] = str(self._config_root / "init_genesis_data.json")

        return peer_config

    @check_param_exist("keys")
    def build_channel_manage_data(self) -> Config:
        if not self.channel_manage_data:
            self.channel_manage_data = make_channel_manage_data(channel_names=self._channel_names, keys=self.keys)

        return self.channel_manage_data

    def write(self):
        self.write_keys()
        self.write_genesis_data()
        self.write_peer_configs()
        self.write_channel_manage_data()
        self.write_monitoring_list()

    @check_param_exist("keys")
    def write_keys(self) -> Iterable[Path]:
        self._config_root.mkdir(exist_ok=True)
        self.key_root.mkdir(parents=True)
        for key in self.keys:
            key.write()

        return (key.path for key in self.keys)

    @check_param_exist("genesis_data")
    def write_genesis_data(self) -> Path:
        self._config_root.mkdir(exist_ok=True)

        genesis_data_path = self._config_root / "init_genesis_data.json"
        dict_write(path=genesis_data_path, dict_obj=self.genesis_data)

        return genesis_data_path

    @check_param_exist("peer_configs")
    def write_peer_configs(self) -> Iterable[Path]:
        self._config_root.mkdir(exist_ok=True)

        paths = []
        for idx, peer_config in enumerate(self.peer_configs):
            config_path = self._config_root / f"test_{idx}_conf.json"
            paths.append(config_path)
            dict_write(config_path, peer_config)

        return paths

    @check_param_exist("channel_manage_data")
    def write_channel_manage_data(self) -> Path:
        self._config_root.mkdir(exist_ok=True)

        channel_manage_data_path = self._config_root / "channel_manage_data.json"
        channel_manage_data = copy.deepcopy(self.channel_manage_data)

        for channel_name in channel_manage_data.keys():
            each_channel = channel_manage_data[channel_name]
            each_channel["peers"] = each_channel["peers"][:self.main_reps_count]

        dict_write(channel_manage_data_path, channel_manage_data)

        return channel_manage_data_path

    @check_param_exist("channel_manage_data")
    def write_monitoring_list(self) -> Path:
        self._config_root.mkdir(exist_ok=True)

        monitoring_list_path = self._config_root / "monitoring_list.json"
        dict_write(monitoring_list_path, self.channel_manage_data)

        return monitoring_list_path


def start_as_configure(args):
    total_reps_count: int = args.total_reps
    main_reps_count: int = args.main_reps
    channel_names: list = args.channel_names
    password: str = args.password
    config_root: Path = Path(args.config_output).expanduser().resolve()

    # TODO: if args.interactive:
    #   ...

    try:
        config_gen = ConfigGenerator(
            config_root=config_root,
            total_reps_count=total_reps_count,
            main_reps_count=main_reps_count,
            channel_names=channel_names,
            key_password=password,
        )
        config_gen.build()
        config_gen.write()
    except Exception as e:
        print(f"{e.__class__.__name__}: {e}")
