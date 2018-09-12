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
"""A module for the Genesis Block Validation"""

import json
import logging
import re
from typing import Dict

from loopchain import utils, configure as conf
from loopchain.blockchain import Transaction
from .. import HashGenerator, get_genesis_tx_hash_generator


# Changing the import location will cause a pickle error.


class GenesisBlockValidator:
    def __init__(self, hash_generator: HashGenerator):
        self.hash_generator = hash_generator

    def validate(self, tx: Transaction) -> bool:
        try:
            if self.__validate_params(tx.accounts):
                return True
            return False
        except Exception as e:
            logging.debug(f"GenesisBlockValidator:: tx {tx.tx_hash} validate fail {e}")
            return False

    def init_genesis_tx(self, genesis_data: dict):
        # utils.logger.spam(f"genesis_Data :: init_genesis_tx >>>{genesis_data}")
        if genesis_data is None:
            return False, None

        keys = genesis_data.keys()
        if "accounts" not in keys:
            return False, None

        if not self.__validate_params(genesis_data["accounts"]):
            logging.debug(f"Invalid genesis data::accounts")
            return False, None

        tx = Transaction()
        expected_tx_hash = self.hash_generator.generate_hash(genesis_data)
        utils.logger.spam(f"expected_tx_hash::{expected_tx_hash}")
        if not tx.put_genesis_data(genesis_data, expected_tx_hash):
            return False, None

        return True, tx

    def __validate_params(self, genesis_data):
        for account in genesis_data:
            keys = account.keys()
            if "address" not in keys or "balance" not in keys or "name" not in keys:
                return False
            if not self.__is_address(account['address']):
                return False
            if account["balance"] is None:
                return False

        logging.debug(f"success validation of balance.")
        return True

    def __is_address(self, address) -> bool:
        if address[:2] != 'hx':
            logging.debug(f"address {address} must have header hx")
            return False
        if re.fullmatch(r"^[0-9a-f]{40}$", address[2:] or "") is None:
            logging.debug(f"address {address} address contents data must have : ")
            return False

        logging.debug(f"success validation of address.")
        return True

    def restore(self, tx_json):
        tx = Transaction()
        if self.__init_genesis_tx(tx_json, tx):
            return tx
        else:
            return None

    def __init_genesis_tx(self, genesis_dumped_data: str, tx: Transaction):
        genesis_data = json.loads(genesis_dumped_data)
        tx_hash = self.hash_generator.generate_hash(genesis_data)
        return tx.put_genesis_data(genesis_data, tx_hash)


_validators: Dict[str, GenesisBlockValidator] = {}


def refresh_genesis_tx_validators():
    _validators.clear()
    for channel_name in conf.CHANNEL_OPTION.keys():
        refresh_genesis_tx_validator(channel_name)


def refresh_genesis_tx_validator(channel_name_):
    version = conf.CHANNEL_OPTION[channel_name_]["genesis_tx_hash_version"]

    if channel_name_ in _validators:
        validator = _validators[channel_name_]
        if validator.hash_generator.origin_generator.version == version:
            return

    hash_generator = get_genesis_tx_hash_generator(channel_name_)
    _validators[channel_name_] = GenesisBlockValidator(hash_generator)


def get_genesis_tx_validator(channel_name_):
    try:
        refresh_genesis_tx_validator(channel_name_)
        return _validators[channel_name_]

    except KeyError as e:
        logging.error(f"Cannot find tx validator for channel{channel_name_}")
        raise e


refresh_genesis_tx_validators()
