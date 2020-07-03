"""util functions for unittest"""

import asyncio
import json
import logging
from typing import Optional

import loopchain.utils as util
from loopchain import configure as conf
from loopchain.baseservice import CommonSubprocess
from loopchain.blockchain.blocks import Block
from loopchain.blockchain.transactions import Transaction, TransactionBuilder, TransactionVersioner
from loopchain.blockchain.types import Address
from loopchain.peer import Signer
from loopchain.protos import loopchain_pb2_grpc
from loopchain.store.key_value_store import KeyValueStoreError, KeyValueStore
from loopchain.utils import loggers
from loopchain.utils.message_queue import StubCollection

loggers.set_preset_type(loggers.PresetType.develop)
loggers.update_preset()


def run_peer_server_as_process(port, radiostation_port=conf.PORT_RADIOSTATION, group_id=None, score=None):
    args = ['python3', 'loopchain.py', 'peer', '-d', '-p', str(port),
            '-r', f"{util.get_private_ip()}:{radiostation_port}"]
    logging.debug(f"run_peer_server_as_process ({args})")
    return CommonSubprocess(args)


def run_peer_server_as_process_and_stub(
        port, radiostation_port=conf.PORT_RADIOSTATION, group_id=None, score=None, timeout=None, wait=True):
    if timeout is None:
        timeout = conf.TIMEOUT_FOR_PEER_INIT

    process = run_peer_server_as_process(port, radiostation_port, group_id, score)

    async def _wait():
        StubCollection().amqp_target = conf.AMQP_TARGET
        StubCollection().amqp_key = f"{util.get_private_ip()}:{port}"

        logging.debug(f'{StubCollection().amqp_key} peer hello')

        await StubCollection().create_peer_stub()
        await StubCollection().peer_stub.async_task().hello()

        logging.debug(f'{StubCollection().amqp_key} peer hello complete')

    if wait:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            future = asyncio.ensure_future(_wait())
            loop.run_until_complete(future)
            loop.stop()
            loop.close()
        except Exception as e:
            logging.warning(f"Exception in loop : {e}")

    stub, channel = util.get_stub_to_server(f"localhost:{port}", stub_class=loopchain_pb2_grpc.PeerServiceStub)
    return process, stub


def print_testname(testname):
    print("\n======================================================================")
    print("Test %s Start" % testname)
    print("======================================================================")


def make_key_value_store(store_identity="") -> Optional[KeyValueStore]:
    store_default_path = './' + (store_identity, "db_test")[store_identity == ""]
    store_path = store_default_path
    store = None
    retry_count = 0

    while store is None and retry_count < conf.MAX_RETRY_CREATE_DB:
        try:
            uri = f"file://{store_path}"
            store = KeyValueStore.new(uri, create_if_missing=True)
            logging.debug(f"make key value store uri: {uri}")
        except KeyValueStoreError:
            store_path = store_default_path + str(retry_count)
        retry_count += 1

    return store


def create_basic_tx(peer_auth: Signer) -> Transaction:
    """
    :param peer_auth:
    :return: transaction
    """
    tx_builder = TransactionBuilder.new("0x3", TransactionVersioner())
    tx_builder.private_key = peer_auth._private_key
    tx_builder.to_address = Address("hx3f376559204079671b6a8df481c976e7d51b3c7c")
    tx_builder.value = 1
    tx_builder.step_limit = 100000000
    tx_builder.nid = 3
    return tx_builder.build()


def add_genesis_block():
    tx_info = None
    channel = conf.LOOPCHAIN_DEFAULT_CHANNEL

    if "genesis_data_path" in conf.CHANNEL_OPTION[channel]:
        genesis_data_path = conf.CHANNEL_OPTION[channel]['initial_genesis_block_data_file_path']
        util.logger.spam(f"Try load a file of initial genesis block from ({genesis_data_path})")
        try:
            with open(genesis_data_path) as json_file:
                tx_info = json.load(json_file)["transaction_data"]
                util.logger.spam(f"generate_genesis_block::tx_info >>>> {tx_info}")

        except FileNotFoundError as e:
            exit(f"cannot open json file in ({genesis_data_path}): "
                 f"{e}")

    block = Block(channel_name=channel)
    block.block_status = BlockStatus.confirmed
    genesis_validator = get_genesis_tx_validator(channel)
    is_valid, tx = genesis_validator.init_genesis_tx(tx_info)

    if is_valid:
        block.put_genesis_transaction(tx)

    block.generate_block()
    # 제네시스 블럭을 추가 합니다.
    return block
