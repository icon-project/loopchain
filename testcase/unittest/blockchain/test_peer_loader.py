import json
import os
from pathlib import Path

import pytest

from loopchain import configure as conf
from loopchain.baseservice import ObjectManager
from loopchain.baseservice.rest_client import RestClient
from loopchain.blockchain.blockchain import BlockChain
from loopchain.blockchain.peer_loader import PeerLoader
from loopchain.blockchain.types import Hash32
from loopchain.channel.channel_property import ChannelProperty
from loopchain.channel.channel_service import ChannelService
from loopchain.peer.block_manager import BlockManager

CHANNEL_NAME = "icon_dex"
REP_COUNT = 20

LAST_BLOCK_REPS_HASH: Hash32 = Hash32(os.urandom(Hash32.size))
CONFIG_CREP_ROOT_HASH: Hash32 = Hash32(os.urandom(Hash32.size))


@pytest.fixture(autouse=True)
def setup(mocker):
    # Mock Channel name
    ChannelProperty().name = CHANNEL_NAME

    # Mock BlockChain
    blockchain = mocker.MagicMock(BlockChain)
    blockchain.find_preps_by_roothash = mocker.MagicMock(return_value=lambda rep_root_hash: rep_root_hash)

    # Mock BlockManager
    block_manager: BlockManager = mocker.MagicMock(BlockManager)
    block_manager.blockchain = blockchain

    # Mock ChannelService
    channel_service: ChannelService = mocker.MagicMock(ChannelService)
    channel_service.block_manager = block_manager

    # Finally, set mocked ChannelService to ObjectManager
    ObjectManager().channel_service = channel_service

    yield

    # Teardown
    ChannelProperty().name = None
    ObjectManager().channel_service = None


class TestPeerLoaderDB:
    @pytest.fixture
    def has_last_block(self, request) -> bool:
        """Create last_block contains reps_hash if passed param is True."""
        blockchain = ObjectManager().channel_service.block_manager.blockchain
        exist_last_block = request.param

        if exist_last_block:
            blockchain.last_block.header.reps_hash = LAST_BLOCK_REPS_HASH
        else:
            blockchain.last_block = None

        return exist_last_block

    @pytest.fixture
    def has_crep_root_hash_in_config(self, request) -> bool:
        """Suppose that crep_root_hash has been supplied by config file."""
        is_hash_supplied = request.param
        orig_crep_root_hash = conf.CHANNEL_OPTION[ChannelProperty().name]["crep_root_hash"]

        if is_hash_supplied:
            conf.CHANNEL_OPTION[ChannelProperty().name]["crep_root_hash"] = CONFIG_CREP_ROOT_HASH.hex_0x()
        else:
            # FIXME: Not allowed `crep_root_hash` to be None!
            conf.CHANNEL_OPTION[ChannelProperty().name]["crep_root_hash"] = CONFIG_CREP_ROOT_HASH.hex_0x()

        yield is_hash_supplied

        conf.CHANNEL_OPTION[ChannelProperty().name]["crep_root_hash"] = orig_crep_root_hash

    @pytest.mark.parametrize("has_crep_root_hash_in_config", [True, False], ids=["HashInConfig", "NotHashInConfig"], indirect=True)
    @pytest.mark.parametrize("has_last_block", [True, False], ids=["LastBlock", "NotLastBlock"], indirect=True)
    def test_load_from_db(self, has_last_block, has_crep_root_hash_in_config):
        crep_root_hash = conf.CHANNEL_OPTION[ChannelProperty().name]["crep_root_hash"]
        PeerLoader._load_peers_from_db(crep_root_hash)

        blockchain = ObjectManager().channel_service.block_manager.blockchain

        if has_last_block:
            assert blockchain.last_block
            blockchain.find_preps_by_roothash.assert_called_with(LAST_BLOCK_REPS_HASH)
        else:
            assert not blockchain.last_block
            blockchain.find_preps_by_roothash.assert_called_with(CONFIG_CREP_ROOT_HASH)


class TestPeerLoaderFile:
    FILE_NAME: str = Hash32(os.urandom(Hash32.size)).hex_0x()
    REPS = [{
        "id": Hash32(os.urandom(Hash32.size)).hex_0x(),
        "peer_target": f"{order}:{order}",
        "order": order
    } for order in range(REP_COUNT)]
    CHANNEL_MANAGE_DATA = {
        CHANNEL_NAME: {
            "peers": REPS
        }
    }

    @pytest.fixture
    def has_rep_data_file(self, tmp_path, mocker, request) -> bool:
        """Create channel_manage_data.json file if passed param is True."""
        exist_channel_manage_data = request.param
        file_path: Path = tmp_path / self.FILE_NAME
        mocker.patch.object(conf, "CHANNEL_MANAGE_DATA_PATH", file_path)

        if exist_channel_manage_data:
            # Write data
            with open(file_path, "w") as f:
                json.dump(self.CHANNEL_MANAGE_DATA, f)

            assert file_path.exists()
            assert Path(conf.CHANNEL_MANAGE_DATA_PATH).exists()
        else:
            assert not file_path.exists()
            assert not Path(conf.CHANNEL_MANAGE_DATA_PATH).exists()

        return exist_channel_manage_data

    @pytest.mark.parametrize("has_rep_data_file", [True, False], ids=["InFile", "NotInFile"], indirect=True)
    def test_load_from_file(self, has_rep_data_file):
        if has_rep_data_file:
            peers = PeerLoader._load_peers_from_file()

            for order, peer in enumerate(peers):
                assert peer["id"] == self.REPS[order]["id"]
                assert peer["p2pEndpoint"] == self.REPS[order]["peer_target"]
        else:
            # FIXME: Not allowed to call when channel_manage_data.json does not exist!
            pass


class TestPeerLoaderRestCall:
    REPS = [{
        "address": Hash32(os.urandom(Hash32.size)).hex_0x(),
        "p2pEndpoint": f"{order}:{order}"
    } for order in range(REP_COUNT)]

    @pytest.fixture
    def patch_for_rest_call(self, mocker, request) -> bool:
        do_patch = request.param
        rs_client = mocker.MagicMock(RestClient)

        if do_patch:
            rs_client.call.return_value = self.REPS
        else:
            rs_client.call.side_effect = ConnectionError()

        # Mock RestClient
        ObjectManager().channel_service.rs_client = rs_client

        yield do_patch

        # Teardown RestClient
        ObjectManager().channel_service.rs_client = None

    @pytest.mark.parametrize("patch_for_rest_call", [True, False], ids=["RestOK", "RestFail"], indirect=True)
    def test_load_from_rest(self, patch_for_rest_call):
        if patch_for_rest_call:
            reps = PeerLoader._load_peers_from_rest_call("test")

            for order, rep in enumerate(reps):
                assert rep["id"] == self.REPS[order]["address"]
                assert rep["p2pEndpoint"] == self.REPS[order]["p2pEndpoint"]
        else:
            with pytest.raises(ConnectionError):
                PeerLoader._load_peers_from_rest_call("test")


class TestPeerLoaderBasicScenario:
    REPS = "reps_data!"

    @pytest.fixture(autouse=True)
    def mock_peer_loader(self, mocker):
        """Mock private methods.

        Then test that the method is called or not in given case.
        """
        mocker.patch.object(PeerLoader, "_load_peers_from_file", return_value="loaded_from_file")
        mocker.patch.object(PeerLoader, "_load_peers_from_rest_call", return_value="loaded_from_rest")
        mocker.patch.object(PeerLoader, "_get_peer_root_hash", return_value="ignore_proof_root!")

    @pytest.fixture
    def has_reps_in_db(self, mocker, request):
        """If passed True, reps_data is found from DB."""
        if request.param:
            mocker.patch.object(PeerLoader, "_load_peers_from_db", return_value="loaded_from_db")
        else:
            mocker.patch.object(PeerLoader, "_load_peers_from_db", return_value=None)

        yield request.param

    @pytest.fixture
    def has_reps_in_file(self, mocker, request, tmp_path):
        """If passed True, reps_data is found from channel_manage_data.json file."""
        file_path: Path = tmp_path / "channel_manage_data.json"
        mocker.patch.object(conf, "CHANNEL_MANAGE_DATA_PATH", file_path)

        if request.param:
            # Create file at given path
            file_path.write_text("")

            assert file_path.exists()
            assert Path(conf.CHANNEL_MANAGE_DATA_PATH).exists()
        else:
            assert not file_path.exists()
            assert not Path(conf.CHANNEL_MANAGE_DATA_PATH).exists()

        yield request.param

    @pytest.mark.parametrize("has_reps_in_file", [True, False], ids=["InFile", "NotInFile"], indirect=True)
    @pytest.mark.parametrize("has_reps_in_db", [True, False], ids=["InDB", "NotInDB"], indirect=True)
    def test_load(self, has_reps_in_db, has_reps_in_file):
        root_hash, reps_data = PeerLoader.load()
        print()
        # print("- Root hash: ", root_hash)
        print("- Reps data: ", reps_data)

        if has_reps_in_db:
            # Reps loaded from db
            PeerLoader._load_peers_from_db.assert_called()
            PeerLoader._load_peers_from_file.assert_not_called()
            PeerLoader._load_peers_from_rest_call.assert_not_called()
        elif has_reps_in_file:
            # Failed to load data from db, but found in file.
            PeerLoader._load_peers_from_db.assert_called()
            PeerLoader._load_peers_from_file.assert_called()
            PeerLoader._load_peers_from_rest_call.assert_not_called()
        else:
            # Failed to load data from db either from file. Try to REST call.
            PeerLoader._load_peers_from_db.assert_called()
            PeerLoader._load_peers_from_file.assert_not_called()
            PeerLoader._load_peers_from_rest_call.assert_called()
