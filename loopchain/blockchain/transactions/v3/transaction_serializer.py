from . import Transaction, HASH_SALT
from .. import TransactionSerializer as BaseTransactionSerializer
from ... import Hash32, Signature, Address


class TransactionSerializer(BaseTransactionSerializer):
    _hash_salt = HASH_SALT

    def to_origin_data(self, tx: 'Transaction'):
        origin_data = dict(tx.raw_data)
        origin_data.pop("signature", None)
        return origin_data

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

        tx_data_copied.pop('signature', None)
        tx_hash = self._hash_generator.generate_hash(tx_data_copied)

        nonce = tx_data.get('nonce')
        if nonce is not None:
            nonce = int(nonce, 16)

        value = tx_data.get('value')
        if value is not None:
            value = int(value, 16)

        return Transaction(
            raw_data=raw_data,
            hash=Hash32(tx_hash),
            signature=Signature.from_base64str(tx_data['signature']),
            timestamp=int(tx_data['timestamp'], 16),
            from_address=Address.fromhex_address(tx_data['from']),
            to_address=Address.fromhex_address(tx_data['to']),
            value=value,
            step_limit=int(tx_data['stepLimit'], 16),
            nonce=nonce,
            nid=int(tx_data['nid'], 16),
            data_type=tx_data.get('dataType'),
            data=tx_data.get('data')
        )

    def get_hash(self, tx_dumped: dict) -> str:
        return tx_dumped['txHash']
