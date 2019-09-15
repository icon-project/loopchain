import time
from typing import Union

import requests
from iconsdk.builder.transaction_builder import TransactionBuilder
from iconsdk.exception import JSONRPCException, DataTypeException
from iconsdk.icon_service import IconService
from iconsdk.providers.http_provider import HTTPProvider
from iconsdk.signed_transaction import SignedTransaction
from iconsdk.wallet.wallet import KeyWallet

from loopchain.blockchain.blocks import Block, BlockSerializer
from loopchain.blockchain.blocks import v0_3
from loopchain.blockchain.transactions import TransactionVersioner


def _get_payload(block_height):
    payload = {
        "jsonrpc": "2.0",
        "method": "icx_getBlock",
        "id": 1234,
    }
    if not block_height == "latest":
        payload["params"] = {
            "height": hex(block_height)
        }
    print("REQ payload: ", payload)

    return payload


def _request(endpoint, payload) -> dict:
    print("Req endpoint: ", endpoint)
    response = requests.post(endpoint, json=payload)
    print("RES: ", response)

    response_as_dict: dict = response.json()
    assert "error" not in response_as_dict

    return response_as_dict


def _get_raw_block(endpoint, block_height) -> dict:
    payload = _get_payload(block_height=block_height)
    raw_block = _request(endpoint, payload)["result"]

    return raw_block


def _convert_raw_block(raw_block: dict, block_version: str) -> Block:
    block_serializer = BlockSerializer.new(block_version, TransactionVersioner())
    block: Block = block_serializer.deserialize(block_dumped=raw_block)
    print("RES block: ", block)

    return block


def get_block(endpoint, nth_block: Union[int, str] = "latest", block_version=v0_3.version) -> Block:
    raw_block = _get_raw_block(endpoint, block_height=nth_block)
    if nth_block == 0:
        raw_block["commit_state"] = None

    block = _convert_raw_block(raw_block, block_version)
    return block


def get_last_block_height(endpoint) -> int:
    raw_block: dict = _get_raw_block(endpoint, block_height="latest")
    block_height = raw_block["height"]

    if isinstance(block_height, str):  # v0.3 block returns its height as hex string
        block_height = int(block_height, 16)

    return block_height


def send_tx(endpoint, wallet: KeyWallet, from_addr=None, to_addr=None) -> str:
    print("REQ endpoint: ", endpoint)
    icon_service = IconService(HTTPProvider(endpoint))

    # Build transaction and sign it with wallet
    transaction = TransactionBuilder()\
        .from_(from_addr or wallet.address)\
        .to(to_addr or wallet.address)\
        .value(10)\
        .step_limit(100000000)\
        .nid(3)\
        .nonce(100)\
        .build()
    signed_transaction = SignedTransaction(transaction, wallet)
    tx_hash = icon_service.send_transaction(signed_transaction=signed_transaction)
    print("Tx hash: ", tx_hash)

    return tx_hash


def get_tx_by_hash(endpoint, tx_hash, max_retry=60):
    icon_service = IconService(HTTPProvider(endpoint))

    is_consensus_completed = False

    interval_sleep_sec = 1
    retry_count = 0
    tx_result = None

    while not is_consensus_completed:
        if retry_count >= max_retry:
            raise RuntimeError(f"Consensus failed!"
                               f"tx hash: {tx_hash}"
                               f"endpoint: {endpoint}")
        try:
            tx_result = icon_service.get_transaction(tx_hash)
        except (JSONRPCException, DataTypeException) as e:
            print(">> Exc: ", e)
            time.sleep(interval_sleep_sec)
            retry_count += 1
        else:
            assert tx_result
            is_consensus_completed = True

    return tx_result
