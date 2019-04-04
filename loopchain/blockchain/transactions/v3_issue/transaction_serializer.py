from loopchain.blockchain.types import Hash32
from loopchain.blockchain.transactions import TransactionSerializer as BaseTransactionSerializer
from loopchain.blockchain.transactions.v3_issue import Transaction, HASH_SALT


class TransactionSerializer(BaseTransactionSerializer):
    _hash_salt = HASH_SALT

    def to_origin_data(self, tx: 'Transaction'):
        return dict(tx.raw_data)

    def to_raw_data(self, tx: 'Transaction'):
        return dict(tx.raw_data)

    def to_full_data(self, tx: 'Transaction'):
        full_data = dict(tx.raw_data)
        full_data['txHash'] = tx.hash.hex()
        return full_data

    def to_db_data(self, tx: 'Transaction'):
        return dict(tx.raw_data)

    def from_(self, tx_data: dict) -> 'Transaction':
        hash_ = self._hash_generator.generate_hash(tx_data)
        timestamp = tx_data['timestamp']

        nid = tx_data['nid']
        nid = int(nid, 16)

        data_type = tx_data['data_type']
        data = tx_data['data']

        return Transaction(
            raw_data=tx_data,
            hash=Hash32(hash_),
            timestamp=timestamp,
            nid=nid,
            data_type=data_type,
            data=data
        )

    def get_hash(self, tx_dumped: dict) -> str:
        return tx_dumped['txHash']
