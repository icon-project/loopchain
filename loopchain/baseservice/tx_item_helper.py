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

import json
import sys

from loopchain.blockchain.transactions import Transaction, TransactionVersioner, TransactionSerializer
from loopchain.protos import loopchain_pb2


class TxItem:
    tx_serializers = {}

    def __init__(self, tx_json: str, channel: str):
        self.channel = channel
        self.__tx_json = tx_json
        self.__len = sys.getsizeof(tx_json) + sys.getsizeof(channel)

    def __len__(self):
        return self.__len

    def get_tx_message(self):
        message = loopchain_pb2.TxSend(
            tx_json=self.__tx_json,
            channel=self.channel)
        return message

    @classmethod
    def create_tx_item(cls, tx_param: tuple, channel: str):
        tx, tx_versioner = tx_param
        tx_serializer = cls.get_serializer(tx, tx_versioner)
        tx_item = TxItem(
            json.dumps(tx_serializer.to_raw_data(tx)),
            channel
        )
        return tx_item

    @classmethod
    def get_serializer(cls, tx: Transaction, tx_versioner: TransactionVersioner):
        if tx.version not in cls.tx_serializers:
            cls.tx_serializers[tx.version] = TransactionSerializer.new(tx.version, tx.type(), tx_versioner)
        return cls.tx_serializers[tx.version]
