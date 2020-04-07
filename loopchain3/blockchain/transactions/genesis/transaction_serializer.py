from loopchain.blockchain.types import Hash32
from loopchain.blockchain.transactions import TransactionSerializer as BaseTransactionSerializer
from loopchain.blockchain.transactions.genesis import Transaction, NID, NTxHash, HASH_SALT


class TransactionSerializer(BaseTransactionSerializer):
    _hash_salt = HASH_SALT

    def to_origin_data(self, tx: 'Transaction'):
        return dict(tx.raw_data)

    def to_raw_data(self, tx: 'Transaction'):
        return dict(tx.raw_data)

    def to_full_data(self, tx: 'Transaction'):
        return dict(tx.raw_data)

    def to_db_data(self, tx: 'Transaction'):
        return dict(tx.raw_data)

    def from_(self, tx_data: dict) -> 'Transaction':
        hash_ = self._hash_generator.generate_hash(tx_data)
        nid = tx_data.get('nid')
        if nid:
            nid = int(nid, 16)
        else:
            if hash_ == NTxHash.mainnet.value:
                nid = NID.mainnet.value
            elif hash_ == NTxHash.testnet.value:
                nid = NID.testnet.value
            else:
                nid = NID.unknown.value

        return Transaction(
            raw_data=tx_data,
            hash=Hash32(hash_),
            signature=None,
            timestamp=0,
            nid=nid,
            accounts=tx_data['accounts'],
            message=tx_data['message']
        )

    def get_hash(self, tx_dumped: dict) -> str:
        return tx_dumped['tx_hash']
