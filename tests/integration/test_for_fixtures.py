import json
import os
import time

import pytest
from iconsdk.wallet.wallet import KeyWallet

from . import conftest
from .conftest import Loopchain


# @pytest.mark.skip
class TestLoopchainBasic:
    channel_name_list = [
        ["test_one_channel"],
        ["ICON_DEX", "DEX_ICON"],
        ["ICON_DEX", "NOCI", "THIRD_cHaNnEl"],
    ]

    def test_generate_wallet_addr(self, tmp_path):
        """Check that wallet generator has no issues in making accounts"""
        wallet_key_path = os.path.join(tmp_path, "test_keystore.key")
        account_addr = conftest.generate_addr(wallet_key_path=wallet_key_path, password="password")

        with open(wallet_key_path) as f:
            content = json.load(f)

        print("KEY_CONTENT: ", content)
        print("accdr: ", account_addr)
        assert isinstance(content, dict)
        assert account_addr.startswith("hx")

    @pytest.mark.parametrize("channel_list", channel_name_list)
    def test_generate_peer_conf_has_valid_channel_names(self, generate_peer_conf_path_list, channel_list):
        """Check that all peer configs have channel name given by list"""
        path_list, _ = generate_peer_conf_path_list(peer_count=1, channel_list=channel_list)
        for each_conf_path in path_list:
            with open(each_conf_path) as f:
                conf_content = json.load(f)

            assert list(conf_content["CHANNEL_OPTION"].keys()) == channel_list

    def test_generate_peer_conf_has_valid_peer_id(self, generate_peer_conf_path_list):
        """Check that all paths contains valid wallets and peer id"""
        path_list, _ = generate_peer_conf_path_list(peer_count=5, channel_list=["channel_no_name"])

        for each_conf_path in path_list:
            with open(each_conf_path) as f:
                conf_content = json.load(f)

            key_path = conf_content["PRIVATE_PATH"]
            key_pass = conf_content["PRIVATE_PASSWORD"]
            addr = conf_content["PEER_ID"]
            assert addr == KeyWallet.load(key_path, key_pass).get_address()

    @pytest.mark.parametrize("peer_count", [1, 2, 3, 4, 5])
    def test_generate_config_contains_desired_peer_count(self, generate_peer_conf_path_list, peer_count):
        """Test that desired number of peer configures have been successfully made"""
        path_list, _ = generate_peer_conf_path_list(peer_count=peer_count, channel_list=["just_test"])

        assert len(path_list) == peer_count

    def test_run_loopchain_with_no_exception(self, xprocess, request, generate_peer_conf_path_list):
        """Test that loopchain runs without any exception

        :raise: AssertionError if error pattern catched while running.
        :raise: RuntimeError if no error pattern catched while running, which means successfully initialized.
        """
        channel_count = int(request.config.getoption("--channel-count"))
        channel_list = [f"channel_{i}" for i in range(channel_count)]
        conf_path_list, _ = generate_peer_conf_path_list(channel_list=channel_list, peer_count=1)
        each_peer_conf = conf_path_list[0]

        Loopchain.pattern = "Errno|[Ee]rror|refused|raise"
        Loopchain.args = ["loop", "peer", "-d", "-o", each_peer_conf]
        Loopchain.end_line = 80 * channel_count
        proc_name = "Exception_detective"

        try:
            with pytest.raises(RuntimeError):
                xprocess.ensure(proc_name, Loopchain)
                raise AssertionError("Exception Found!")
            print("All green. No exception found until timeout.")
        finally:
            proc_info = xprocess.getinfo(proc_name)
            proc_info.terminate()
            time.sleep(3)
