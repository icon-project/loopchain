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

        params.update(tx.extra)
        return params

    def to_raw_data(self, tx: 'Transaction'):
        params = self.to_origin_data(tx)
        params['tx_hash'] = tx.hash.hex()
        params['signature'] = tx.signature.to_base64str()
        return params

    def to_full_data(self, tx: 'Transaction'):
        return self.to_raw_data(tx)

    def from_(self, tx_data: dict) -> 'Transaction':
        tx_data = dict(tx_data)
        tx_data.pop('method', None)

        hash = tx_data.pop('tx_hash', None)
        signature = tx_data.pop('signature', None)
        timestamp = tx_data.pop('timestamp', None)
        from_address = tx_data.pop('from', None)
        to_address = tx_data.pop('to', None)
        value = tx_data.pop('value', None)
        fee = tx_data.pop('fee', None)
        nonce = tx_data.pop('nonce', None)
        extra = tx_data

        return Transaction(
            hash=Hash32.fromhex(hash),
            signature=Signature.from_base64str(signature),
            timestamp=int(timestamp) if timestamp is not None else None,
            from_address=Address.fromhex(from_address),
            to_address=Address.fromhex(to_address),
            value=value,
            fee=fee,
            nonce=nonce,
            extra=extra
        )

    def get_hash(self, tx_dumped: dict) -> str:
        return tx_dumped['tx_hash']
