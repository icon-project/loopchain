import random
import time

import pytest
from iconsdk.builder.transaction_builder import MessageTransactionBuilder
from iconsdk.icon_service import IconService
from iconsdk.providers.http_provider import HTTPProvider
from iconsdk.signed_transaction import SignedTransaction
from iconsdk.wallet.wallet import KeyWallet

from loopchain import conf
from loopchain import utils
from loopchain.blockchain.blocks import Block, BlockSerializer
from loopchain.blockchain.transactions import TransactionVerifier
from loopchain.blockchain.transactions import TransactionVersioner
from loopchain.blockchain.types import VarBytes
from . import conftest
from .conftest import Loopchain

# Global variables
peer_conf_path_list = []  # Peer config file path list. Needed to query peers' information.
genesis_data: dict = {}  # Genesis tx content. Compared with tx in genesis block.


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

    Loopchain.pattern = fr"BroadcastScheduler process\(channel_{channel_count - 1}\) start"
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

        # Store process information for terminate processes at the end of the test
        proc_info = xprocess.getinfo(proc_name)
        proc_info_list.append(proc_info)

    print(f"==========ALL GREEN ==========")
    time.sleep(0.5 * peer_count * channel_count)

    yield

    # Executed here after this fixture's scope ends.
    for proc_info in proc_info_list:
        proc_info.terminate()

    time.sleep(3)  # For additional tests, wait for a moment to cool down.


class TestLoopchain:
    sent_tx_data = {}  # Sent tx data. Needed to be compared whether it equals with the queried one.
    tx_hash_by_channel = {}  # Tx hashes. It collects return values of 'send_transaction'.

    @pytest.mark.parametrize("port, channel_name", conftest.port_channel_list)
    def test_health_check_before_test(self, port, channel_name):
        """Health check before test starts

        **Assertion Tests**:
            - Compare values of `accounts`, `message` and `nid` between queried genesis tx and origin data
        """
        global genesis_data
        expected_data = genesis_data["transaction_data"]

        url = utils.normalize_request_url(str(port), conf.ApiVersion.v3, channel_name)
        print("Req url: ", url)

        icon_service = IconService(HTTPProvider(url))
        genesis_block: dict = icon_service.get_block(0)

        # TODO: dummy data to deserialize block. Fix in iconsdk
        genesis_block["commit_state"] = None
        genesis_block["confirmed_transaction_list"][0]["nid"] = "0x3"

        tx_versioner = TransactionVersioner()
        block_serializer = BlockSerializer.new("0.1a", TransactionVersioner())
        genesis_block: Block = block_serializer.deserialize(block_dumped=genesis_block)
        genesis_tx = list(genesis_block.body.transactions.values())[0]
        print("genesis_tx: ", genesis_tx)

        tv = TransactionVerifier.new("genesis", genesis_tx.type(), tx_versioner)
        tv.verify(genesis_tx)

        assert expected_data["accounts"] == genesis_tx.raw_data["accounts"]
        assert expected_data["message"] == genesis_tx.raw_data["message"]
        assert expected_data["nid"] == genesis_tx.raw_data["nid"]

    @pytest.mark.parametrize("port, channel_name", conftest.port_channel_list)
    def test_get_lastest_block_has_no_error(self, port, channel_name):
        """Test that getLastBlock API has no issue"""
        url = utils.normalize_request_url(str(port), conf.ApiVersion.v3, channel_name)
        icon_service = IconService(HTTPProvider(url))
        block = icon_service.get_block("latest")

        print("REQ url: ", url)
        print("RES block: ", block)

        assert "error" not in block

    def test_send_tx_message(self, request):
        """Test for 'send_transaction'

        .. note::
            Test steps:
                1. Get peer info from first peer
                2. Extract key and password and make wallet
                3. Build message transaction and sign it
                4. Send Tx to first channel.
                5. Await consensus time(currently 0.5 * <<Number of peers>> 'sec')
                6. Repeat from '3'

        .. warnings:: Interval await time is essential, due to consensus completion.

        **Assertion Test**:
            - Check that return value of send_transaction has valid tx hash format.
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

    @pytest.mark.parametrize("port, channel_name", conftest.port_channel_list)
    def test_sent_tx_is_synced(self, port, channel_name):
        """Following test of 'test_send_tx_message'

        Check that send_transaction is successfully completed.

        **Test steps**:
            1. Get tx_hash from previous test
            2. Query tx_hash to first channel
            3. Compare queried tx with original data
            4. Repeat until the channel order reaches to the end

        **Assertion Tests**:
            Check Tx values below
            1. From address
            2. To address
            3. Data (message)
        """
        print("sent_tx_data: ", TestLoopchain.sent_tx_data)

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
