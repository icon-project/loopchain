"""helper class for TxMessages"""

import json
import sys
from typing import TYPE_CHECKING

from loopchain.blockchain.transactions import TransactionSerializer
from loopchain.p2p.grpc_helper.grpc_message import P2PMessage

if TYPE_CHECKING:
    from loopchain.blockchain.transactions import Transaction, TransactionVersioner


class TxItem:
    tx_serializers = {}

    def __init__(self, tx_json: str, channel: str):
        self.channel = channel
        self.__tx_json = tx_json
        self.__len = sys.getsizeof(tx_json) + sys.getsizeof(channel)

    def __len__(self):
        return self.__len

    def get_tx_message(self) -> 'TxSend':
        """Get TxSend message

        :return: 'TxSend' message for send transaction
        """
        return P2PMessage.tx_send(
            tx_json=self.__tx_json,
            channel=self.channel)

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
    def get_serializer(cls, tx: 'Transaction', tx_versioner: 'TransactionVersioner'):
        if tx.version not in cls.tx_serializers:
            cls.tx_serializers[tx.version] = TransactionSerializer.new(tx.version, tx.type(), tx_versioner)
        return cls.tx_serializers[tx.version]
