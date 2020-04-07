from typing import TYPE_CHECKING
from loopchain.blockchain.exception import TransactionInvalidNidError
from loopchain.blockchain.transactions import TransactionVerifier as BaseTransactionVerifier
from loopchain.blockchain.transactions.v3 import TransactionSerializer, HASH_SALT

if TYPE_CHECKING:
    from loopchain.blockchain.transactions import Transaction


class TransactionVerifier(BaseTransactionVerifier):
    _hash_salt = HASH_SALT

    def __init__(self, hash_generator_version: int, raise_exceptions=True):
        super().__init__(hash_generator_version, raise_exceptions)
        self._tx_serializer = TransactionSerializer(hash_generator_version)

    def pre_verify(self, tx: 'Transaction', **kwargs):
        nid = kwargs.get('nid')
        if nid != tx.nid:
            raise TransactionInvalidNidError(tx, nid)
        self.verify(tx, None)

    def verify(self, tx: 'Transaction', blockchain=None):
        self.verify_loosely(tx, blockchain)

    def verify_loosely(self, tx: 'Transaction', blockchain=None):
        self.verify_hash(tx)
        self.verify_signature(tx)
        if blockchain:
            nid = blockchain.find_nid()
            if hex(tx.nid) != nid:
                raise TransactionInvalidNidError(tx, int(nid, 16))
            self.verify_tx_hash_unique(tx, blockchain)
