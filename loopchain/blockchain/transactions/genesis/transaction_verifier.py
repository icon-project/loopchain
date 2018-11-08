from typing import TYPE_CHECKING
from . import TransactionSerializer, HASH_SALT
from .. import TransactionVerifier as BaseTransactionVerifier
from ... import Address

if TYPE_CHECKING:
    from . import Transaction


class TransactionVerifier(BaseTransactionVerifier):
    _hash_salt = HASH_SALT

    def __init__(self, hash_generator_version: int):
        super().__init__(hash_generator_version)
        self._tx_serializer = TransactionSerializer(hash_generator_version)

    def verify(self, tx: 'Transaction', blockchain=None):
        self.verify_hash(tx)
        self.verify_accounts(tx)
        if blockchain:
            self.verify_tx_hash_unique(tx, blockchain)

    def verify_signature(self, tx: 'Transaction'):
        pass

    def verify_accounts(self, tx: 'Transaction'):
        for account in tx.accounts:
            keys = account.keys()
            if "address" not in keys or "balance" not in keys or "name" not in keys:
                raise RuntimeError

            if account["balance"] is None:
                raise RuntimeError

            # An exception will be raised if 'address' is invalid.
            Address.fromhex(account['address'])
