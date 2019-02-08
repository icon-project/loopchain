#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2018 ICON Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""util functions for unittest"""

import asyncio
import json
import leveldb
import logging
import multiprocessing
import os
import random
import time
from sys import platform

import loopchain
import loopchain.utils as util
from loopchain import configure as conf
from loopchain.baseservice import ObjectManager, StubManager, Block, CommonSubprocess
from loopchain.blockchain import Transaction, TransactionBuilder, TransactionVersioner, Address
from loopchain.components import SingletonMetaClass
from loopchain.peer import PeerService, Signer
from loopchain.protos import loopchain_pb2, loopchain_pb2_grpc
from loopchain.radiostation import RadioStationService
from loopchain.utils import loggers
from loopchain.utils.message_queue import StubCollection


loggers.set_preset_type(loggers.PresetType.develop)
loggers.update_preset()


def run_peer_server(port, rs_port=None, group_id=None, score=None, event_for_init=None):
    if rs_port is None:
        rs_port = conf.PORT_RADIOSTATION
    radio_station_target = f"{conf.IP_RADIOSTATION}:{rs_port}"
    ObjectManager().peer_service = PeerService(group_id, radio_station_target)

    if score is not None:
        ObjectManager().peer_service.set_chain_code(score)

    conf.DEFAULT_SCORE_REPOSITORY_PATH = \
        os.path.join(os.path.dirname(__file__), '..', '..', 'resources', 'test_score_repository')
    try:
        ObjectManager().peer_service.serve(port, conf.DEFAULT_SCORE_PACKAGE, event_for_init=event_for_init)
    except FileNotFoundError:
        logging.debug("Score Load Fail")
    except TimeoutError as e:
        logging.exception(e)


def run_radio_station(port, event_for_init: multiprocessing.Event=None):
    RadioStationService().serve(port, event_for_init)


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

    stub, channel = util.get_stub_to_server(target='localhost:' + str(port),
                                            stub_class=loopchain_pb2_grpc.PeerServiceStub,
                                            time_out_seconds=timeout)
    return process, stub


def run_peer_server_as_process_and_stub_manager(
        port, radiostation_port=conf.PORT_RADIOSTATION, group_id=None, score=None, timeout=None):
    process = run_peer_server_as_process(port, radiostation_port, group_id, score)
    stub_manager = StubManager.get_stub_manager_to_server(
        'localhost:' + str(port), loopchain_pb2_grpc.PeerServiceStub, ssl_auth_type=conf.GRPC_SSL_TYPE)
    return process, stub_manager


def run_radio_station_as_process(port):
    args = ['python3', 'loopchain.py', 'rs', '-d', '-p', str(port)]
    logging.debug(f"run_radio_station_as_process ({args})")
    return CommonSubprocess(args)


def run_radio_station_as_process_and_stub_manager(port, timeout=None):
    process = run_radio_station_as_process(port)
    stub_manager = StubManager.get_stub_manager_to_server(
        'localhost:' + str(port), loopchain_pb2_grpc.RadioStationStub, conf.GRPC_SSL_TYPE)
    util.request_server_in_time(stub_manager.stub.GetStatus, loopchain_pb2.StatusRequest(request=""))
    return process, stub_manager


def run_radio_station_as_process_and_stub(port, timeout=None):
    if timeout is None:
        timeout = conf.TIMEOUT_FOR_RS_INIT
    process = run_radio_station_as_process(port)
    stub, channel = util.get_stub_to_server(target='localhost:' + str(port),
                                            stub_class=loopchain_pb2_grpc.RadioStationStub,
                                            time_out_seconds=timeout)
    return process, stub


def run_score_server_as_process(amqp_key):
    args = ['python3', 'loopchain.py', 'score',
            '--channel', conf.LOOPCHAIN_DEFAULT_CHANNEL,
            '--amqp_key', amqp_key,
            '--score_package', "score_package",
            '-d']
    logging.debug(f"run_score_server_as_process ({args})")
    return CommonSubprocess(args)


async def run_score_server_as_process_and_stub_async():
    amqp_key = str(time.time())
    process = run_score_server_as_process(amqp_key)

    StubCollection().amqp_target = conf.AMQP_TARGET
    StubCollection().amqp_key = amqp_key

    logging.debug(f'{StubCollection().amqp_key} score hello')

    await StubCollection().create_score_stub(conf.LOOPCHAIN_DEFAULT_CHANNEL, 'score_package')
    await StubCollection().score_stubs[conf.LOOPCHAIN_DEFAULT_CHANNEL].async_task().hello()

    logging.debug(f'{StubCollection().amqp_key} score hello complete')

    return process, StubCollection().score_stubs[conf.LOOPCHAIN_DEFAULT_CHANNEL]


def print_testname(testname):
    print("\n======================================================================")
    print("Test %s Start" % testname)
    print("======================================================================")


def make_level_db(db_name=""):
    db_default_path = './' + (db_name, "db_test")[db_name == ""]
    db_path = db_default_path
    blockchain_db = None
    retry_count = 0

    while blockchain_db is None and retry_count < conf.MAX_RETRY_CREATE_DB:
        try:
            blockchain_db = leveldb.LevelDB(db_path, create_if_missing=True)
            logging.debug("make level db path: " + db_path)
        except leveldb.LevelDBError:
            db_path = db_default_path + str(retry_count)
        retry_count += 1

    return blockchain_db


def close_open_python_process():
    # ubuntu patch
    if platform == "darwin":
        os.system("pkill -f python")
        os.system("pkill -f Python")
    else:
        os.system("pgrep -f python | tail -$((`pgrep -f python | wc -l` - 1)) | xargs kill -9")


def clean_up_temp_db_files(kill_process=True):
    from pathlib import Path
    loopchain_root = Path(os.path.dirname(loopchain.__file__)).parent

    if kill_process:
        close_open_python_process()

    print(f"loopchain root : {loopchain_root}")

    os.system(f'rm -rf $(find {loopchain_root} -name db_*)')
    os.system(f'rm -rf $(find {loopchain_root} -name *test_db*)')
    os.system(f'rm -rf $(find {loopchain_root} -name *_block)')
    os.system(f"rm -rf {loopchain_root}/testcase/db_*")
    os.system(f"rm -rf {loopchain_root}/.storage")
    os.system(f"rm -rf {loopchain_root}/log")
    os.system(f"rm -rf {loopchain_root}/chaindb_*")
    os.system(f"rm -rf {loopchain_root}/blockchain_db*")
    os.system(f"rm -rf {loopchain_root}/block_confirm_db*")
    os.system(f"rm -rf {loopchain_root}/genesis_db*")
    os.system(f"rm -rf {loopchain_root}/testcase/chaindb_*")
    os.system(f"rm -rf {loopchain_root}/sample_score")
    os.system(f"rm -rf {loopchain_root}/testcase/sample_score")
    os.system(f"rm -rf {loopchain_root}/certificate_db")
    os.system(f"rm -rf {loopchain_root}/resources/test_score_deploy")
    os.system(f"rm -rf {loopchain_root}/resources/test_score_repository/loopchain")
    time.sleep(1)


def clean_up_mq():
    os.system("rabbitmqctl stop_app")
    os.system("rabbitmqctl reset")
    os.system("rabbitmqctl start_app")


def create_basic_tx(peer_auth: Signer) -> Transaction:
    """
    :param peer_auth:
    :return: transaction
    """
    tx_builder = TransactionBuilder.new("0x3", TransactionVersioner())
    tx_builder.private_key = peer_auth.private_key
    tx_builder.to_address = Address("hx3f376559204079671b6a8df481c976e7d51b3c7c")
    tx_builder.value = 1
    tx_builder.step_limit = 100000000
    tx_builder.nid = 3
    return tx_builder.build()


def create_default_peer_auth() -> Signer:
    channel = list(conf.CHANNEL_OPTION)[0]
    peer_auth = Signer.from_channel(channel)
    return peer_auth


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


class TestServerManager(metaclass=SingletonMetaClass):
    """

    """

    def __init__(self):
        self.__test_port_diff = random.randrange(1, 30) * -50
        self.__radiostation_port = conf.PORT_RADIOSTATION + self.__test_port_diff

        # rs and peer info is tuple (process, stub_manager, port)
        self.__rs_info = ()
        self.__peer_info = {}  # {num:peer_info}
        self.__score = None

    def start_servers(self, peer_count, score=None):
        """Start BlockChain network rs and peer

        :param peer_count: num of peers but 0 means start only RS.
        :return:
        """
        logging.debug("TestServerManager start servers")
        self.__score = score

        # run radio station
        process, stub_manager = run_radio_station_as_process_and_stub_manager(self.__radiostation_port)
        self.__rs_info = (process, stub_manager, self.__radiostation_port)
        time.sleep(2)

        for i in range(peer_count):
            peer_port = conf.PORT_PEER + (i * 7) + self.__test_port_diff
            process, stub_manager = run_peer_server_as_process_and_stub_manager(
                peer_port, self.__radiostation_port, score=score)
            self.__peer_info[i] = (process, stub_manager, peer_port)
            time.sleep(2)

    def stop_all_server(self):
        for i in self.__peer_info:
            self.__peer_info[i][1].call_in_times(
                "Stop",
                loopchain_pb2.StopRequest(reason="TestServerManager"), conf.GRPC_TIMEOUT)
        self.__rs_info[1].call_in_times(
            "Stop",
            loopchain_pb2.StopRequest(reason="TestServerManager"), conf.GRPC_TIMEOUT)

        time.sleep(2)

        for i in self.__peer_info:
            self.__peer_info[i][0].join()
        self.__rs_info[0].join()

    def stop_peer(self, num):
        self.__peer_info[num][1].call_in_times(
            "Stop",
            loopchain_pb2.StopRequest(reason="TestServerManager"), conf.GRPC_TIMEOUT)
        time.sleep(2)
        self.__peer_info[num][0].join()

    def start_peer(self, num):
        peer_port = conf.PORT_PEER + (num * 7) + self.__test_port_diff
        process, stub_manager = run_peer_server_as_process_and_stub_manager(
            peer_port, self.__radiostation_port, score=self.__score)
        self.__peer_info[num] = (process, stub_manager, peer_port)
        time.sleep(1)

    def add_peer(self):
        num = 0
        return num

    def get_stub_rs(self):
        return self.__rs_info[1].stub

    def get_stub_peer(self, num=0):
        return self.__peer_info[num][1].stub

    def get_port_rs(self):
        return self.__radiostation_port

    def get_port_peer(self, num):
        return self.__peer_info[num][2]

    def status(self):
        """

        :return: json object for ServerManager status
        """
        pass
