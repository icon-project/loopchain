import binascii
import random
import time

import pytest
from iconsdk.builder.transaction_builder import MessageTransactionBuilder
from iconsdk.icon_service import IconService
from iconsdk.providers.http_provider import HTTPProvider
from iconsdk.signed_transaction import SignedTransaction
from iconsdk.wallet.wallet import KeyWallet
from loopchain.blockchain.types import VarBytes

from loopchain import conf
from loopchain import utils
from . import conftest
from .conftest import Loopchain

# Global variables
peer_conf_path_list = []  # Peer config file path list. Needed to query peers' information.
genesis_data: dict = None  # Genesis tx content. Compared with tx in genesis block.


@pytest.fixture(scope="class", autouse=True)
def loopchain_proc(xprocess, request, generate_peer_conf_path_list_extended):
    """Set up loopchain launcher for integration test"""
    # Define test environment
    global peer_conf_path_list
    global genesis_data
    proc_info_list = []  # Loopchain process info. Needed to tear down processes.

    peer_type = request.config.getoption("--peer-type")
    peer_count = int(request.config.getoption("--peer-count"))
    channel_count = int(request.config.getoption("--channel-count"))
    channel_list = [f"channel_{i}" for i in range(channel_count)]
    print(f"\n*--- Test env:\n Peer Type: {peer_type}, Peer Count: {peer_count}, Channel Count: {channel_count}")

    Loopchain.pattern = f"BroadcastScheduler process\(channel_{channel_count - 1}\) start"
    Loopchain.end_line = 80 * peer_count * channel_count

    # Generate configure files. Run only one time at the beginning of the test.
    print("*--- Generate peer configure path list...")
    peer_conf_path_list, channel_manage_data_path = \
        generate_peer_conf_path_list_extended(peer_count=peer_count, channel_list=channel_list)
    print("> peer_conf_path: ", peer_conf_path_list)
    print("> channel_manage_data_path: ", channel_manage_data_path)

    genesis_data = conftest.get_genesis_data(conf_path_list=peer_conf_path_list)

    # Run Each peer
    for peer_order in range(peer_count):
        peer_conf_path = peer_conf_path_list[peer_order]
        Loopchain.args = ["loop", peer_type, "-d", "-o", peer_conf_path]
        proc_name = f"peer{peer_order}"

        print(f"==========PEER_{peer_order} READY TO START ==========")
        xprocess.ensure(proc_name, Loopchain)

        # Store process infomation for terminate processes at the end of the test
        proc_info = xprocess.getinfo(proc_name)
        proc_info_list.append(proc_info)

    print(f"==========ALL GREEN ==========")
    time.sleep(0.5 * peer_count * channel_count)

    yield True

    # Executed after this fixture's scope ends.
    for proc_info in proc_info_list:
        proc_info.terminate()

    time.sleep(3)  # For additional tests, need a moment to cool down.


class TestLoopchain:
    sent_tx_data = {}  # Sent tx data. Needed to be compared whether it equals with the queried one.
    tx_hash_by_channel = {}  # Tx hashes. It collects return values of 'send_transaction'.

    # @pytest.mark.skip
    def test_health_check_before_test(self, request):
        """Health check before test starts

        Test steps:
            1. Get genesis local file which is created when the test starts.
            2. Get rich account's balance (God is not used. Generally third one.)
            3. Get balance from 'All channels of All peers'.
            4. Compare original balance with queried one.

        Assertion Tests:
            1. Queried balance == Expected balance
            2. All queried balance has same value
        """
        global genesis_data
        print("Genesis data: ", genesis_data)

        peer_count = int(request.config.getoption("--peer-count"))
        channel_count = int(request.config.getoption("--channel-count"))

        genesis_node = genesis_data["transaction_data"]["accounts"][2]
        target_account = genesis_node["address"]
        expected_balance = int(genesis_node["balance"], 16)
        print("Address of billionaire account: ", target_account)

        querried_balance_list = []

        for peer_order in range(peer_count):
            port = 9000 + (peer_order * 100)

            for channel_num in range(channel_count):
                url = utils.normalize_request_url(str(port), conf.ApiVersion.v3, f"channel_{channel_num}")
                print("Req url: ", url)
                icon_service = IconService(HTTPProvider(url))
                queried_balance = icon_service.get_balance(target_account)
                print("Queried balance: ", queried_balance)

                assert queried_balance == expected_balance
                querried_balance_list.append(queried_balance)
                time.sleep(0.5)

        print("Balance all: ", querried_balance_list)
        assert len(set(querried_balance_list)) == 1

    # @pytest.mark.skip
    def test_compare_genesis_tx_with_initial_data(self):
        """Test that the first peer is initialized with given genesis data

        Similar to 'test_health_check_before_test',
        but it tries to catch all critical values of genesis tx in order to ensure test reliablity.

        # TODO: Could be changed or enhanced when the block version 0.3 is applied.

        Test steps:
            1. Get genesis tx
            2. Query genesis tx
            3. Compare two Txs
        """
        global genesis_data
        expected_data = genesis_data["transaction_data"]
        print("EXPECTED tx_data: ", expected_data)

        # TODO: iconsdk does not provide channel select on current version (1.0.9).
        url = utils.normalize_request_url("9000", conf.ApiVersion.v3, "channel_0")
        icon_service = IconService(HTTPProvider(url))
        block = icon_service.get_block(0)
        tx_list = block["confirmed_transaction_list"][0]
        print("tx_list: ", tx_list)

        assert tx_list["message"] == expected_data["message"]
        assert tx_list["nid"] == expected_data["nid"]
        assert tx_list["accounts"] == expected_data["accounts"]

    @pytest.mark.skip(reason="Could be a redundant test")
    def test_all_peers_running_with_synced_data(self, request):
        """Test that all peers are alive"""
        peer_count = int(request.config.getoption("--peer-count"))

        for peer_order in range(1, peer_count):
            port = 9000 + (peer_order * 100)
            url = utils.normalize_request_url(str(port), conf.ApiVersion.v3, "channel_0")
            icon_service = IconService(HTTPProvider(url))
            block = icon_service.get_block("latest")

            print("REQ url: ", url)
            print("RES block: ", block)

            assert "error" not in block

    # @pytest.mark.skip
    def test_send_tx_message(self, request):
        """Test for 'send_transaction'

        Note:
            Uses Message Type Transaction.
            From address is equal to To address.
            Interval await time is essential, due to consensus completion and different tx hashes between channels.

        Test steps:
            1. Get peer info from first peer
            2. Extract key and password and make wallet
            3. Build message transaction and sign it
            4. Send Tx to first channel.
            5. Await consensus time(currently 0.5 * <<Number of peers>> 'sec')
            6. Repeat from '3'

        Assertion Test:
            1. Check that return value of send_transaction has valid tx hash format.
        """
        global peer_conf_path_list

        channel_count = int(request.config.getoption("--channel-count"))

        from_peer = conftest.get_peer_info(conf_path_list=peer_conf_path_list, order=0)
        key_path = from_peer["PRIVATE_PATH"]
        key_pass = from_peer["PRIVATE_PASSWORD"]
        wallet = KeyWallet.load(key_path, key_pass)

        for channel_order in range(channel_count):
            # Create message
            byte_msg = f"test_msg on {random.randint(0, 44444)}".encode("utf-8")
            msg = VarBytes(byte_msg).hex_0x()

            # Address
            from_to_address = wallet.get_address()

            # Store tx data to compare with queried one later.
            channel_name = f"channel_{channel_order}"
            TestLoopchain.sent_tx_data[channel_name] = {
                "from": from_to_address,
                "to": from_to_address,
                "msg": msg
            }

            # Build transaction and sign it with wallet
            transaction_data = {
                "from": from_to_address,
                "to": from_to_address,
                "step_limit": 100000000,
                "nid": 3,
                "nonce": 100,
                "data": msg,
            }
            transaction = MessageTransactionBuilder().from_dict(transaction_data).build()
            signed_transaction = SignedTransaction(transaction, wallet)

            # Send tx
            url = utils.normalize_request_url("9000", conf.ApiVersion.v3, channel_name)
            print("Req url: ", url)
            icon_service = IconService(HTTPProvider(url))
            tx_hash = icon_service.send_transaction(signed_transaction)
            print("Tx hash: ", tx_hash)

            assert tx_hash.startswith("0x")
            TestLoopchain.tx_hash_by_channel[channel_name] = tx_hash

            await_sec = 0.5 * len(peer_conf_path_list)
            print(f"Await consensus...({await_sec})")
            time.sleep(await_sec)

        print("ALL TXs by channel: ", TestLoopchain.tx_hash_by_channel)
        final_await_sec = 1 * channel_count
        print(f"Await consensus final...({final_await_sec})")
        time.sleep(final_await_sec)

    # @pytest.mark.skip
    def test_sent_tx_is_synced(self, request):
        """Following test of 'test_send_tx_message'

        Check that send_transaction is successfully completed.

        Test steps:
            1. Get tx_hash from previous test
            2. Query tx_hash to first channel
            3. Compare queried tx with original data
            4. Repeat until the channel order reaches to the end

        Assertion Tests:
            Check Tx values below
            1. From address
            2. To address
            3. Data (message)
        """
        print("sent_tx_data: ", TestLoopchain.sent_tx_data)

        peer_count = int(request.config.getoption("--peer-count"))
        channel_count = int(request.config.getoption("--channel-count"))

        for peer_order in range(peer_count):
            port = 9000 + (peer_order * 100)
            for channel_order in range(channel_count):
                channel_name = f"channel_{channel_order}"
                url = utils.normalize_request_url(str(port), conf.ApiVersion.v3, channel_name)
                print("Req url: ", url)
                icon_service = IconService(HTTPProvider(url))
                tx_hash = TestLoopchain.tx_hash_by_channel[channel_name]
                print("Tx hash to be queried: ", tx_hash)
                queried_tx = icon_service.get_transaction(tx_hash)
                print("Tx result: ", queried_tx)

                assert queried_tx["from"] == TestLoopchain.sent_tx_data[channel_name]["from"]
                assert queried_tx["to"] == TestLoopchain.sent_tx_data[channel_name]["to"]
                assert queried_tx["data"] == TestLoopchain.sent_tx_data[channel_name]["msg"]

                time.sleep(0.5)
