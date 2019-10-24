from typing import TYPE_CHECKING
from loopchain.blockchain.transactions import TransactionVerifier as BaseTransactionVerifier
from loopchain.blockchain.transactions.v3_issue import TransactionSerializer, HASH_SALT

if TYPE_CHECKING:
    from loopchain.blockchain.transactions import Transaction


class TransactionVerifier(BaseTransactionVerifier):
    _allow_unsigned = True
    _hash_salt = HASH_SALT

    def __init__(self, hash_generator_version: int, raise_exceptions=True):
        super().__init__(hash_generator_version, raise_exceptions)
        self._tx_serializer = TransactionSerializer(hash_generator_version)

    def pre_verify(self, tx: 'Transaction', **kwargs):
        self.verify(tx, None)

    def verify(self, tx: 'Transaction', blockchain=None):
        self.verify_loosely(tx, blockchain)

    def verify_loosely(self, tx: 'Transaction', blockchain=None):
        self.verify_hash(tx)
        self.verify_signature(tx)
        if blockchain:
            self.verify_tx_hash_unique(tx, blockchain)
