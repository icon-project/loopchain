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
"""helper class for TxItem"""

import abc
import json
import pickle
import sys

import loopchain.utils as util
from loopchain.blockchain import Transaction
from loopchain.protos import loopchain_pb2


class TxItem:

    def __init__(self, channel):
        self.__channel = channel

    @property
    def channel(self):
        return self.__channel

    @abc.abstractmethod
    def get_tx_message(self):
        pass


class TxItemPickle(TxItem):

    def __init__(self, tx_dump: bytes, channel: str):
        super().__init__(channel)
        self.__tx_dump = tx_dump
        self.__len = sys.getsizeof(tx_dump) + sys.getsizeof(channel)

    def __len__(self):
        return self.__len

    def get_tx_message(self):
        message = loopchain_pb2.TxSend(
            tx=self.__tx_dump,
            channel=self.channel)
        return message


class TxItemJson(TxItem):

    def __init__(self, tx_json: str, channel: str):
        super().__init__(channel)
        self.__tx_json = tx_json
        self.__len = sys.getsizeof(tx_json) + sys.getsizeof(channel)

    def __len__(self):
        return self.__len

    def get_tx_message(self):
        message = loopchain_pb2.TxSend(
            tx_json=self.__tx_json,
            channel=self.channel)
        return message


class TxItemHelper(metaclass=abc.ABCMeta):

    @classmethod
    @abc.abstractclassmethod
    def create_tx_item(cls, create_tx_param: Transaction):
        pass


class TxItemHelperPickle(TxItemHelper):

    @classmethod
    def create_tx_item(cls, create_tx_param):
        # util.logger.spam(f"tx_item_helper_pickle:create_tx_item create_tx_param({create_tx_param})")
        tx_item = TxItemPickle(
            pickle.dumps(create_tx_param),
            create_tx_param.meta[Transaction.CHANNEL_KEY]
        )
        return tx_item


class TxItemHelperJson(TxItemHelper):

    @classmethod
    def create_tx_item(cls, create_tx_param):
        # util.logger.spam(f"tx_item_helper_json:create_tx_item")
        tx_item = TxItemJson(
            create_tx_param.json_dumps(),
            create_tx_param.meta[Transaction.CHANNEL_KEY]
        )
        return tx_item


class TxItemHelperIcx(TxItemHelper):
    @classmethod
    def create_tx_item(cls, create_tx_param: Transaction):
        # util.logger.spam(f"tx_item_helper_icx:create_tx_item create_tx_param({create_tx_param})")
        tx_item = TxItemJson(
            json.dumps(create_tx_param.icx_origin_data),
            create_tx_param.meta[Transaction.CHANNEL_KEY]
        )
        return tx_item
