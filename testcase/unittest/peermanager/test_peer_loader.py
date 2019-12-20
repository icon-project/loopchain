import json
from pathlib import Path

import pytest

from loopchain import configure as conf
from loopchain.baseservice import ObjectManager, RestClient
from loopchain.blockchain.blockchain import BlockChain
from loopchain.channel.channel_property import ChannelProperty
from loopchain.channel.channel_service import ChannelService
from loopchain.peer.block_manager import BlockManager
from loopchain.peermanager.peer_loader import PeerLoader


class Params:
    CHANNEL_NAME = "icon_dex"
    PEER_NUM = 4
    FILE_PATH: Path = None

    DB_FLAG: bool = None
    FILE_FLAG: bool = None
    REST_CALL_FLAG: bool = None

    REPS_DB = [{
        "id": f"hx{str(order)*32}",
        "p2pEndpoint": f"{order}: {order}"
    } for order in range(PEER_NUM)]

    REPS_FILE = [{
        "id": f"hx{str(order)*32}",
        "peer_target": f"{order}: {order}"
    } for order in range(1, PEER_NUM+1)]

    CHANNEL_MANAGE_DATA = {
        CHANNEL_NAME: {
            "peers": [{
                "id": peer["id"],
                "peer_target": peer["peer_target"],
                "order": order
            } for order, peer in enumerate(REPS_FILE, start=1)]
        }
    }

    REPS_REST = [{
        "address": f"hx{str(order)*32}",
        "p2pEndpoint": f"{order}: {order}"
    } for order in range(2, PEER_NUM+2)]

    LOADED_REPS_FROM_DB = [{
        "id": peer["id"],
        "p2pEndpoint": peer["p2pEndpoint"]
    } for peer in REPS_DB]

    LOADED_REPS_FROM_FILE = [{
        "id": peer["id"],
        "p2pEndpoint": peer["peer_target"]
    } for peer in REPS_FILE]

    LOADED_REPS_FROM_REST = [{
        "id": peer["address"],
        "p2pEndpoint": peer["p2pEndpoint"]
    } for peer in REPS_REST]


@pytest.fixture(autouse=True)
def mocking_channel_name():
    ChannelProperty().name = Params.CHANNEL_NAME

    yield

    ChannelProperty().name = None


@pytest.fixture(autouse=True)
def mocking_channel_service(mocker):
    block_manager: BlockManager = mocker.MagicMock(BlockManager)
    block_manager.blockchain = mocker.MagicMock(BlockChain)

    channel_service: ChannelService = mocker.MagicMock(ChannelService)
    channel_service.block_manager = block_manager

    ObjectManager().channel_service = channel_service

    yield

    ObjectManager().channel_service = None


@pytest.fixture(params=[False, True], ids=["DB", "DB"])
def patch_for_db(mocker, request):
    Params.DB_FLAG = request.param

    blockchain = ObjectManager().channel_service.block_manager.blockchain
    if Params.DB_FLAG:
        blockchain.find_preps_by_roothash = mocker.MagicMock(return_value=Params.REPS_DB)
    else:
        blockchain.find_preps_by_roothash = mocker.MagicMock(return_value=[])

    yield

    Params.DB_FLAG = None


@pytest.fixture(params=[False, True], ids=["FILE", "FILE"])
def patch_for_file(tmp_path, mocker, request):
    Params.FILE_FLAG = request.param

    if Params.FILE_FLAG:
        Params.FILE_PATH = tmp_path / "channel_manage_data.json"
        mocker.patch.object(conf, "CHANNEL_MANAGE_DATA_PATH", Params.FILE_PATH)

        with open(Params.FILE_PATH, "w") as f:
            json.dump(Params.CHANNEL_MANAGE_DATA, f)
    else:
        never_exist_path = "never_exist.json"
        mocker.patch.object(conf, "CHANNEL_MANAGE_DATA_PATH", never_exist_path)
        assert not Path(never_exist_path).exists()

    yield

    Params.FILE_PATH = None
    Params.FILE_FLAG = None


@pytest.fixture(params=[False, True], ids=["REST", "REST"])
def patch_for_rest_call(mocker, request):
    Params.REST_CALL_FLAG = request.param

    rs_client = mocker.MagicMock(RestClient)
    if Params.REST_CALL_FLAG:
        rs_client.call.return_value = Params.REPS_REST
    else:
        rs_client.call.side_effect = ConnectionError()

    ObjectManager().channel_service.rs_client = rs_client

    yield

    Params.REST_CALL_FLAG = None
    ObjectManager().channel_service.rs_client = None


class TestPeerLoader:
    def _test_load_db(self, result):
        assert result == Params.LOADED_REPS_FROM_DB

    def _test_load_file(self, result):
        assert result == Params.LOADED_REPS_FROM_FILE

        with open(Params.FILE_PATH) as f:
            channel_manage_data: dict = json.load(f)

        expected_peer_data = channel_manage_data[Params.CHANNEL_NAME]["peers"]

        for actual, expected in zip(result, expected_peer_data):
            assert actual["id"] == expected["id"]
            assert actual["p2pEndpoint"] == expected["peer_target"]

    def _test_load_rest_call(self, result):
        assert result == Params.LOADED_REPS_FROM_REST

        for actual, expected in zip(result, Params.REPS_REST):
            assert actual["id"] == expected["address"]
            assert actual["p2pEndpoint"] == expected["p2pEndpoint"]

    def test_load(self, patch_for_db, patch_for_file, patch_for_rest_call):
        loaded_reps = None
        try:
            loaded_reps = PeerLoader.load()
        except Exception as e:
            print(f"Exception: {e}")

        if Params.DB_FLAG:
            self._test_load_db(loaded_reps)
        elif Params.FILE_FLAG:
            self._test_load_file(loaded_reps)
        elif Params.REST_CALL_FLAG:
            self._test_load_rest_call(loaded_reps)
        else:
            assert not any([Params.DB_FLAG, Params.FILE_FLAG, Params.REST_CALL_FLAG])
