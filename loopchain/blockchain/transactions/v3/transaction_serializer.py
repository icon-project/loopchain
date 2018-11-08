from . import Transaction, HASH_SALT
from .. import TransactionSerializer as BaseTransactionSerializer
from ... import Hash32, Signature, Address


class TransactionSerializer(BaseTransactionSerializer):
    _hash_salt = HASH_SALT

    def extract(self, tx: 'Transaction'):
        params = {
            "version": Transaction.version,
            "from": tx.from_address.hex_hx(),
            "to": tx.to_address.hex_hx(),
            "value": hex(tx.value),
            "stepLimit": hex(tx.step_limit),
            "timestamp": hex(tx.timestamp),
            "nid": hex(tx.nid)
        }
        if tx.nonce is not None:
            params['nonce'] = hex(tx.nonce)

        if tx.data is not None and tx.data_type is not None:
            if isinstance(tx.data, str):
                params["data"] = tx.data.encode('utf-8').hex()
            else:
                params["data"] = tx.data
            params["dataType"] = tx.data_type
        return params

    def serialize(self, tx: 'Transaction'):
        params = self.extract(tx)
        params['signature'] = tx.signature.to_base64str()
        return params

    def deserialize(self, tx_data: dict) -> 'Transaction':
        tx_data_copied = dict(tx_data)
        tx_data_copied.pop('signature', None)
        tx_data_copied.pop('txHash', None)

        tx_hash = self._hash_generator.generate_hash(tx_data_copied)

        nonce = tx_data.get('nonce')
        if nonce is not None:
            nonce = int(nonce, 16)

        data = tx_data.get('data')
        if data is not None and isinstance(data, str):
            data = bytes.fromhex(data).decode('utf-8')

        return Transaction(
            hash=Hash32(tx_hash),
            signature=Signature.from_base64str(tx_data['signature']),
            timestamp=int(tx_data['timestamp'], 16),
            from_address=Address.fromhex(tx_data['from']),
            to_address=Address.fromhex(tx_data['to']),
            value=int(tx_data['value'], 16),
            step_limit=int(tx_data['stepLimit'], 16),
            nonce=nonce,
            nid=int(tx_data['nid'], 16),
            data_type=tx_data.get('dataType'),
            data=data
        )

