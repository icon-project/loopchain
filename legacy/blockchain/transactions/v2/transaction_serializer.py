from legacy.blockchain.types import Hash32, Signature, ExternalAddress, int_fromhex, int_fromstr
from legacy.blockchain.transactions import TransactionSerializer as BaseTransactionSerializer
from legacy.blockchain.transactions.v2 import Transaction, HASH_SALT


class TransactionSerializer(BaseTransactionSerializer):
    _hash_salt = HASH_SALT

    def to_origin_data(self, tx: 'Transaction'):
        origin_data = dict(tx.raw_data)
        origin_data.pop("tx_hash", None)
        origin_data.pop("signature", None)
        origin_data.pop("method", None)
        return origin_data

    def to_raw_data(self, tx: 'Transaction'):
        return dict(tx.raw_data)

    def to_full_data(self, tx: 'Transaction'):
        params = dict(tx.raw_data)
        params['method'] = tx.method
        return params

    def to_db_data(self, tx: 'Transaction'):
        return self.to_full_data(tx)

    def from_(self, tx_data: dict) -> 'Transaction':
        tx_data_copied = dict(tx_data)

        tx_data_copied.pop('method', None)
        hash = tx_data_copied.pop('tx_hash', None)
        signature = tx_data_copied.pop('signature', None)
        timestamp = tx_data_copied.pop('timestamp', None)
        from_address = tx_data_copied.pop('from', None)
        to_address = tx_data_copied.pop('to', None)
        value = tx_data_copied.pop('value', None)
        fee = tx_data_copied.pop('fee', None)
        nonce = tx_data_copied.pop('nonce', None)
        extra = tx_data_copied

        value = int_fromhex(value)
        fee = int_fromhex(fee)

        if nonce is not None:
            nonce = int_fromstr(nonce)

        return Transaction(
            raw_data=tx_data,
            hash=Hash32.fromhex(hash, ignore_prefix=True, allow_malformed=False),
            signature=Signature.from_base64str(signature),
            timestamp=int(timestamp) if timestamp is not None else None,
            from_address=ExternalAddress.fromhex(from_address, ignore_prefix=False, allow_malformed=True),
            to_address=ExternalAddress.fromhex(to_address, ignore_prefix=False, allow_malformed=True),
            value=value,
            fee=fee,
            nonce=nonce,
            extra=extra,
        )

    def get_hash(self, tx_dumped: dict) -> str:
        return tx_dumped['tx_hash']
