from . import Transaction, HASH_SALT
from .. import TransactionSerializer as BaseTransactionSerializer
from ... import Hash32, Signature, Address


class TransactionSerializer(BaseTransactionSerializer):
    _hash_salt = HASH_SALT

    def to_origin_data(self, tx: 'Transaction'):
        params = {
            "from": tx.from_address.hex_xx(),
            "to": tx.to_address.hex_xx(),
            "value": tx.value,
            "fee": tx.fee
        }
        if tx.timestamp is not None:
            params['timestamp'] = str(tx.timestamp)
        if tx.nonce is not None:
            params['nonce'] = tx.nonce
        return params

    def to_raw_data(self, tx: 'Transaction'):
        params = self.to_origin_data(tx)
        params['tx_hash'] = tx.hash.hex()
        params['signature'] = tx.signature.to_base64str()
        return params

    def to_full_data(self, tx: 'Transaction'):
        return self.to_raw_data(tx)

    def from_(self, tx_data: dict) -> 'Transaction':
        nonce = tx_data.get('nonce')
        timestamp = tx_data.get('timestamp')

        return Transaction(
            hash=Hash32.fromhex(tx_data['tx_hash']),
            signature=Signature.from_base64str(tx_data['signature']),
            timestamp=int(timestamp) if timestamp is not None else None,
            from_address=Address.fromhex(tx_data['from']),
            to_address=Address.fromhex(tx_data['to']),
            value=tx_data['value'],
            fee=tx_data['fee'],
            nonce=nonce
        )

    def get_hash(self, tx_dumped: dict) -> str:
        return tx_dumped['tx_hash']
