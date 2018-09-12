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
"""A module for Transaction Validation"""

import logging
import traceback

from typing import Dict
from loopchain import configure as conf
from loopchain.blockchain import Transaction
from . import TxValidateStrategy
from .. import HashGenerator, get_tx_hash_generator

# Changing the import location will cause a pickle error.
import loopchain_pb2


class TxValidator:
    def __init__(self, channel, send_tx_type_, hash_generator: HashGenerator):
        self.send_tx_type = send_tx_type_

        self.__signature_validate_strategy = None
        self.__channel = channel
        self.__tx_validate_strategy = TxValidateStrategy.create(send_tx_type_, hash_generator)

    @property
    def hash_generator(self):
        return self.__tx_validate_strategy.hash_generator

    def validate_dumped_tx_message(self, tx_dumped) -> Transaction:
        """

        :param tx_dumped:
        :return: if validate success reutrn Trasnaction, else return None
        """
        try:
            return self.__tx_validate_strategy.validate_dumped_tx_message(tx_dumped, self.__channel)
        except Exception as e:
            logging.warning(f"{e}, tx_dumped : {tx_dumped}")
            raise e

    def validate(self, tx) -> bool:
        """validate tx(hash, signature)

        :param tx: transaction
        :return: validate result
        """
        try:
            return self.__tx_validate_strategy.validate(tx)
        except BaseException as e:
            traceback.print_exc()
            logging.warning(f"Trasaction validation failed. {e}")
            return False

    def restore(self, tx_dumped) -> Transaction:
        """restore dumped tx

        :param tx_dumped: dumped tx
        :return: restored Tx
        """
        return self.__tx_validate_strategy.restore(tx_dumped, self.__channel)

    def load_dumped_tx(self, tx_send: loopchain_pb2.TxSend):
        return self.__tx_validate_strategy.load_dumped_tx(tx_send)


_validators: Dict[str, TxValidator] = {}


def refresh_tx_validators():
    _validators.clear()
    for channel_name in conf.CHANNEL_OPTION.keys():
        refresh_tx_validator(channel_name)


def refresh_tx_validator(channel_name_):
    send_tx_type = conf.CHANNEL_OPTION[channel_name_]["send_tx_type"]
    version = conf.CHANNEL_OPTION[channel_name_]["tx_hash_version"]

    if channel_name_ in _validators:
        validator = _validators[channel_name_]
        if validator.send_tx_type == send_tx_type and \
           validator.hash_generator.origin_generator.version == version:
            return

    hash_generator = get_tx_hash_generator(channel_name_)
    _validators[channel_name_] = TxValidator(channel_name_, send_tx_type, hash_generator)


def get_tx_validator(channel_name_):
    try:
        refresh_tx_validator(channel_name_)
        return _validators[channel_name_]

    except KeyError as e:
        logging.error(f"Cannot find tx validator for channel{channel_name_}")
        raise e


refresh_tx_validators()
