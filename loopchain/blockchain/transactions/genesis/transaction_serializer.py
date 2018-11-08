from . import Transaction, NTxHash, NID, HASH_SALT
from .. import TransactionSerializer as BaseTransactionSerializer


class TransactionSerializer(BaseTransactionSerializer):
    _hash_salt = HASH_SALT

    def extract(self, tx: 'Transaction'):
        if tx.hash == NTxHash.mainnet.value or tx.hash == NTxHash.testnet.value:
            return {
                "accounts": list(tx.accounts),
                "message": tx.message
            }
        else:
            return {
                "nid": hex(tx.nid),
                "accounts": list(tx.accounts),
                "message": tx.message
            }

    def serialize(self, tx: 'Transaction'):
        return self.extract(tx)

    def deserialize(self, tx_data: dict) -> 'Transaction':
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
            hash=hash_,
            signature=None,
            timestamp=0,
            nid=nid,
            accounts=tx_data['accounts'],
            message=tx_data['message']
        )
