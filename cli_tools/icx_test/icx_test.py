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

from collections import Counter

import aiohttp
import asyncio
import binascii
import json
import logging
import random
import time
from jsonrpcclient import HTTPClient
from secp256k1 import PrivateKey
from terminaltables import SingleTable
from urllib.parse import urlparse

from cli_tools.icx_test.icx_wallet import IcxWallet
from loopchain import configure as conf
from loopchain import utils as util


def icx_main(http_client: HTTPClient=None, wallet: IcxWallet=None):
    print("\nJsonRPC Client (TEST)")
    print("1. Connect to Peer and Address")
    print("2. icx_sendTransaction")
    print("3. icx_getTransactionResult")
    print("4. icx_getBalance")
    print("5. icx_getTotalSupply")
    print("6. icx_getLastBlock")
    print("7. icx_getBlockByHash")
    print("8. icx_getBlockByHeight")
    print("9. icx_getTransactionByAddress")
    print("10. icx_getTransactionByHash")
    print("11. Performance test")
    print("0. Back")
    choice = input(" >>  ")

    if choice == "0":
        from cli_tools.loopchain_private_tools import demotool
        demotool.main_menu()
    else:
        globals()["menu" + choice](http_client, wallet)
    return


def menu1(http_client=None, wallet=None):
    print("\nConnect to Peer and Address")
    print("\nInput Peer Target [IP]:[port] (default '' -> 127.0.0.1:9000, [port] -> 127.0.0.1:[port] "
          "/ OR domain address after 'https://')")
    url_input = input(" >>  ")

    print("\nEnter the version of json rpc request. (default '' -> 'v3')")
    print("1. v2")
    print("2. v3")
    version_input = input(" >>  ")
    if version_input == "1":
        version_input = 'v2'
    elif version_input == "2" or version_input == "":
        version_input = 'v3'
    else:
        print("Invalid input, please try again.\n")
        icx_main()

    http_client = util.normalize_request_url(url_input, version_input)
    http_client = HTTPClient(http_client)

    print(f"YOUR REQUEST URL IS : {http_client.endpoint}")
    print("\n1. Login (Enter)")
    print("2. Make new address")
    input_number = input(" >>  ")
    if input_number == "1" or input_number == "":
        print(f"Choose address to login (default '' -> god address({wallet_list[0].address}))")
        for i, wallet in enumerate(wallet_list):
            if i == 0:
                print(f"{i + 1}. {wallet.address} (GOD)")
            elif i == 1:
                print(f"{i + 1}. {wallet.address} (TREASURY)")
            else:
                print(f"{i + 1}. {wallet.address} (test{i - 1})")
        input_choice = input(" >>  ")
        if input_choice == "":
            wallet = wallet_list[0]
            print(f"connected to god address: {wallet.address}")
        else:
            wallet = wallet_list[int(input_choice) - 1]
            print(f"connected to address: {wallet.address}")
    elif input_number == "2":
        wallet = IcxWallet()
        wallet_list.append(wallet)
        logging.debug(f"make new wallet : {wallet}")
    else:
        print("Invalid input, please try again.\n")
        return

    icx_main(http_client, wallet)


def menu2(http_client, wallet):
    if wallet is None:
        print(f"NOTICE! you should connect to peer first. Please enter number 1.")
        icx_main()

    method = "icx_sendTransaction"
    print(f"\nJsonRPC {method}")
    print(f"Enter the address of the receiver: (default '' -> 3. test1 address({wallet_list[2].address})")
    input_address = input(" >>  ")
    input_address = input_address or wallet_list[2].address

    print(f"Enter value: (default '' -> 1 ICX)")
    value_input = input(" >>  ")
    value_input = float(value_input) if value_input else 1.0

    print(f"check your fee: 0.01 ICX")

    repeat_times = input(f"\nEnter repeat times: default 1 >>  ")
    for i in range(int(repeat_times if repeat_times != "" else 1)):
        wallet.to_address = input_address
        wallet.value = value_input
        wallet.message = "hello"
        if 'v2' in http_client.endpoint:
            http_client.request(method, wallet.create_icx_origin())
        elif 'v3' in http_client.endpoint:
            response = http_client.request(method, wallet.create_icx_origin_v3())
            wallet.last_tx_hash = response
        time.sleep(random.uniform(0, 0.5))

    time.sleep(1)
    req = http_client.request("icx_getBalance", address=wallet.address)

    if 'v2' in http_client.endpoint:
        balance = int(req['response'], 16) / 10 ** 18
    elif 'v3' in http_client.endpoint:
        balance = int(req, 16) / 10 ** 18
    logging.debug(f"YOUR BALANCE IS : {balance} ICX")

    icx_main(http_client, wallet)


def menu3(http_client, wallet):
    method = "icx_getTransactionResult"
    if wallet is None:
        print(f"NOTICE! you should connect to peer first. Please enter number 1.")
        icx_main()

    last_tx_hash = wallet.last_tx_hash

    print(f"\nJsonRPC {method}")
    print(f"Enter the tx hash: (default '' -> {last_tx_hash})")
    tx_hash = input(" >>  ")
    tx_hash = tx_hash or last_tx_hash

    if tx_hash:
        if 'v2' in http_client.endpoint:
            if tx_hash.startswith('0x'):
                tx_hash = tx_hash.replace('0x', '')
            response = http_client.request(method, tx_hash=tx_hash)
        elif 'v3' in http_client.endpoint:
            response = http_client.request(method, txHash=tx_hash)
        pretty_json = json.dumps(response, indent=2)
        print(f"{pretty_json}")
    else:
        print("Invalid tx_hash.")

    icx_main(http_client, wallet)


def menu4(http_client, wallet):
    method = "icx_getBalance"
    if wallet is None:
        print(f"NOTICE! you should connect to peer first. Please enter number 1.")
        icx_main()

    print(f"\nJsonRPC {method}")
    req = http_client.request(method, address=wallet.address)

    if 'v2' in http_client.endpoint:
        balance = int(req['response'], 16) / 10 ** 18
    elif 'v3' in http_client.endpoint:
        balance = int(req, 16) / 10 ** 18
    logging.debug(f"YOUR BALANCE IS : {balance} ICX")
    icx_main(http_client, wallet)


def menu5(http_client, wallet):
    method = "icx_getTotalSupply"
    if wallet is None:
        print(f"NOTICE! you should connect to peer first. Please enter number 1.")
        icx_main()

    print(f"\nJsonRPC {method}")
    req = http_client.request(method)

    if 'v2' in http_client.endpoint:
        balance = int(req['response'], 16) / 10 ** 18
        logging.debug(f"TOTAL SUPPLY IS : {balance} ICX")
    elif 'v3' in http_client.endpoint:
        balance = int(req, 16) / 10 ** 18
        logging.debug(f"TOTAL SUPPLY IS : {balance} ICX")

    icx_main(http_client, wallet)


def menu6(http_client, wallet):
    method = "icx_getLastBlock"
    if wallet is None:
        print(f"NOTICE! you should connect to peer first. Please enter number 1.")
        icx_main()

    print(f"\nJsonRPC {method}")
    response = http_client.request(method)
    pretty_json = json.dumps(response, indent=2)
    print(f"{pretty_json}")

    icx_main(http_client, wallet)


def menu7(http_client, wallet):
    method = "icx_getBlockByHash"
    if wallet is None:
        print(f"NOTICE! you should connect to peer first. Please enter number 1.")
        icx_main()

    last_block_response = http_client.request('icx_getLastBlock')

    if 'v2' in http_client.endpoint:
        last_block_hash = last_block_response['block']['block_hash']
        if last_block_hash.startswith('0x'):
            last_block_hash = last_block_hash.replace('0x', '')
    elif 'v3' in http_client.endpoint:
        last_block_hash = last_block_response['block_hash']
        if not last_block_hash.startswith('0x'):
            last_block_hash = f"0x{last_block_hash}"

    print(f"\nJsonRPC {method}")
    print(f"Enter the hash : (default: last block hash('{last_block_hash}'))")
    input_hash = input(" >>  ")
    if input_hash == '':
        input_hash = last_block_hash

    block_response = http_client.request(method, hash=input_hash)
    pretty_json = json.dumps(block_response, indent=2)
    print(pretty_json)
    icx_main(http_client, wallet)


def menu8(http_client, wallet):
    method = "icx_getBlockByHeight"
    if wallet is None:
        print(f"NOTICE! you should connect to peer first. Please enter number 1.")
        icx_main()

    print(f"\nJsonRPC {method}")
    print(f"Enter the height : (default '0')")
    height = input(" >>  ")
    if height == '':
        height = '0'
    if 'v2' in http_client.endpoint:
        response = http_client.request(method, height=height)
    elif 'v3' in http_client.endpoint:
        response = http_client.request(method, height=hex(int(height)))
    pretty_json = json.dumps(response, indent=2)
    print(f"{pretty_json}")
    icx_main(http_client, wallet)


def menu9(http_client, wallet):
    method = "icx_getTransactionByAddress"
    if wallet is None:
        print(f"NOTICE! you should connect to peer first. Please enter number 1.")
        icx_main()
    if 'v3' in http_client.endpoint:
        print(f"This method does not support for v3.")
        icx_main(http_client, wallet)

    print(f"\nJsonRPC {method}")
    index = 0
    while True:
        response = http_client.request(method, address=wallet.address, index=index)
        pretty_json = json.dumps(response, indent=2)
        print(f"{pretty_json}")
        if response['next_index'] == 0:
            print("\nEnd of index")
            break
        print("\nPlease press Enter to continue")
        choice = input(" >>  ")
        if choice == "":
            index = response['next_index']
        else:
            print("Invalid input, please try again.\n")
            icx_main()
    icx_main(http_client, wallet)


def menu10(http_client, wallet):
    method = "icx_getTransactionByHash"
    if wallet is None:
        print(f"NOTICE! you should connect to peer first. Please enter number 1.")
        icx_main()
    if 'v2' in http_client.endpoint:
        print(f"This method does not support for v2.")
        icx_main(http_client, wallet)

    last_tx_hash = wallet.last_tx_hash

    print(f"\nJsonRPC {method}")
    print(f"Enter the tx hash: (default '' -> {last_tx_hash})")
    tx_hash = input(" >>  ")
    tx_hash = tx_hash or last_tx_hash

    if tx_hash:
        response = http_client.request(method, txHash=tx_hash)
        pretty_json = json.dumps(response, indent=2)
        print(f"{pretty_json}")
    else:
        print("Invalid tx_hash.")

    icx_main(http_client, wallet)


def menu11(http_client=None, wallet=None):
    print(f"\nPerformance test\n")
    print("1. icx_sendTransaction")
    print("2. icx_getBalance")
    print("3. icx_getLastBlock")
    print("4. icx_getTotalSupply")
    print("5. icx_getBlockByHeight")
    print("\n0. Back")

    choice = input(" >>  ")
    if choice == "0":
        icx_main()
    else:
        globals()["menu11_" + choice](http_client)
    return


def menu11_1(http_client):
    print("icx_sendTransaction Performance Test")

    performance_run_test('icx_sendTransaction', http_client)
    menu11(http_client)


def menu11_2(http_client):
    print("icx_getBalance Performance Test")

    performance_run_test('icx_getBalance', http_client)
    menu11(http_client)


def menu11_3(http_client):
    print("icx_getLastBlock Performance Test")

    performance_run_test('icx_getLastBlock', http_client)
    menu11(http_client)


def menu11_4(http_client):
    print("icx_getTotalSupply Performance Test")

    performance_run_test('icx_getTotalSupply', http_client)
    menu11(http_client)


def menu11_5(http_client):
    print("icx_getBlockByHeight Performance Test")
    if not http_client:
        default_url = util.normalize_request_url(url_input="", version='v2')
        http_client = HTTPClient(default_url)
    response = http_client.request('icx_getLastBlock')
    last_block_height = response['block']['height']

    performance_run_test('icx_getBlockByHeight', http_client, last_block_height)
    menu11(http_client)


def performance_run_test(method_type, http_client, *args):
    peers, total_tx_time, total_tx_count = performance_make_params(http_client)

    async def _request(url, json_data):
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=json_data):
                return

    async def _run():
        interval = total_tx_time / total_tx_count
        current_tx_count = 0
        start_time = time.time()

        tasks = []
        while True:
            current_time = time.time() - start_time + interval
            current_ratio = current_time / total_tx_time
            current_target_tx_count = total_tx_count * current_ratio
            current_target_tx_count = min(current_target_tx_count, total_tx_count)

            while current_tx_count < current_target_tx_count:
                for peer in peers:
                    request_data = performance_make_request_data(peer, len(tasks), method_type, *args)
                    task = asyncio.ensure_future(_request(peer, request_data))
                    tasks.append(task)
                current_tx_count += 1

            await asyncio.sleep(interval)

            if current_tx_count >= total_tx_count:
                break

        total_tx_count_all_peers = total_tx_count * len(peers)
        print(f"Total tx {total_tx_count} * {len(peers)} = {total_tx_count_all_peers}")
        print(f"Duration {time.time() - start_time}")
        print("Waiting for complete...")

        results = await asyncio.gather(*tasks, return_exceptions=True)
        results = ("Fail" if result else "Success" for result in results)

        duration = time.time() - start_time
        print(f"Complete Duration {duration}")
        print("Done.\n")

        result_dict = dict()
        for key, count in Counter(results).items():
            print(f"{key}: {count}")
            if key == "Success":
                result_dict["Success"] = count
            else:
                result_dict["Fail"] = count

        print(f"TPS per peer: {result_dict['Success'] / duration}")
        if 'Fail' in result_dict.keys():
            failure_rate = round((result_dict['Fail'] / total_tx_count_all_peers) * 100, 3)
            print(f"The failure rate: {failure_rate}%")
        else:
            failure_rate = 0
            print("YEAH! 100% Successful.")

        result_table = [['Request type', 'num of peers', 'total tx', 'complete Duration', 'TPS per peer',
                         'failure rate (%)']]
        result_table.append(
            [method_type,
             len(peers),
             f"{total_tx_count} * {len(peers)} = {total_tx_count_all_peers}",
             duration,
             f"{result_dict['Success'] / duration}",
             failure_rate]
        )
        table = SingleTable(result_table)
        print(table.table)

    loop: asyncio.BaseEventLoop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        loop.run_until_complete(_run())
        loop.stop()
    finally:
        loop.close()


def performance_make_request_data(peer_url, count, method_type, *args):
    random_client: IcxWallet = random.choice(wallet_list[3:])
    if method_type == 'icx_sendTransaction':
        wallet: IcxWallet = wallet_list[0]
        wallet.is_logging = False
        wallet.to_address = random_client.address
        wallet.value = 1
        wallet.message = "hello"
        if 'v2' in peer_url:
            return wallet.create_icx_origin(is_raw_data=True)
        elif 'v3' in peer_url:
            return wallet.create_icx_origin_v3(is_raw_data=True)
    elif method_type == 'icx_getBalance':
        request_data = {
            "jsonrpc": "2.0",
            "method": method_type,
            "id": count,
            "params": {
                "address": random_client.address
            }
        }
        return request_data
    elif method_type == 'icx_getLastBlock' or method_type == 'icx_getTotalSupply':
        request_data = {
            "jsonrpc": "2.0",
            "method": method_type,
            "id": count,
            "params": {}
        }
        return request_data
    elif method_type == 'icx_getBlockByHeight':
        last_block_height = args[0]
        if 'v2' in peer_url:
            random_height = str(random.randrange(0, last_block_height + 1))
        elif 'v3' in peer_url:
            random_height = hex(random.randrange(0, last_block_height + 1))
        request_data = {
            "jsonrpc": "2.0",
            "method": method_type,
            "id": count,
            "params": {
                "height": random_height
            }
        }
        return request_data
    else:
        raise RuntimeError(f"Unexpected method type {method_type}")


def performance_make_params(http_client):
    print("\nEnter duration. (default '' -> 1 second)")
    total_tx_time = input(" >>  ")
    total_tx_time = int(total_tx_time) if total_tx_time else 1
    print("Enter test type. 0) The number of transactions. 1) TPS")
    test_type = input(" >>  ")
    test_type = int(test_type) if test_type else 0
    if test_type == 0:
        print("Enter count of the tx per one peer. (default '' -> 1 tx)")
        total_tx_count = input(" >>  ")
        total_tx_count = int(total_tx_count) if total_tx_count else 1
    elif test_type == 1:
        print("Enter TPS per one peer. (default '' -> 1 tps)")
        target_tps = input(" >>  ")
        target_tps = int(target_tps) if target_tps else 1
        total_tx_count = target_tps * total_tx_time
    else:
        print("Invalid input, please try again.\n")
        menu11(http_client)
        return
    print("Enter peer's addresses. (default '' -> 'the connected peer' or 'localhost:9000')")
    peers = input(" >>  ")
    peers = peers.split()

    print("Enter the version of json rpc request. (default '' -> 'v3')")
    print("1. v2")
    print("2. v3")
    version_input = input(" >>  ")
    if version_input == "1":
        version_input = conf.ApiVersion.v2.name
    elif version_input == "2" or version_input == "":
        version_input = conf.ApiVersion.v3.name

    if peers:
        # Normalize addresses
        peers = [util.normalize_request_url(peer, version_input) for peer in peers]
    else:
        if http_client:
            parse_obj = urlparse(http_client.endpoint)
            url_without_version = f"{parse_obj.scheme}://{parse_obj.netloc}"
            peer_url = util.normalize_request_url(url_without_version, version_input)
            peers.append(peer_url)
        else:
            default_url = util.normalize_request_url(url_input="", version=version_input)
            peers.append(default_url)
    print("Peers.")
    for peer in peers:
        print(peer)
    return peers, total_tx_time, total_tx_count


wallet_list = []
with open("./cli_tools/icx_test/address_list_test.txt") as f:
    key_and_address = f.readlines()
    for each in key_and_address:
        private_key = each.split(maxsplit=2)[0]
        deserialized = PrivateKey(binascii.unhexlify(private_key))
        wallet_address = IcxWallet(deserialized)
        wallet_list.append(wallet_address)


# Main Program
if __name__ == "__main__":
    icx_main()
