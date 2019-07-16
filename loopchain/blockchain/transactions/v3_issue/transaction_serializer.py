from loopchain.blockchain.types import Hash32, Signature, Address
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
        tx_data_copied = dict(tx_data)
        tx_data_copied.pop('txHash', None)
        raw_data = dict(tx_data_copied)

        tx_hash = self._hash_generator.generate_hash(tx_data_copied)

        return Transaction(
            raw_data=raw_data,
            hash=Hash32(tx_hash),
            signature=None,
            timestamp=int(tx_data['timestamp'], 16),
            data_type=tx_data.get('dataType'),
            data=tx_data.get('data')
        )

    def get_hash(self, tx_dumped: dict) -> str:
        return tx_dumped['txHash']
