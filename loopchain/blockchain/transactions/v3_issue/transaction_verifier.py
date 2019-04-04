from typing import TYPE_CHECKING
from loopchain.blockchain.transactions import TransactionVerifier as BaseTransactionVerifier
from loopchain.blockchain.transactions.v3_issue import TransactionSerializer, HASH_SALT

if TYPE_CHECKING:
    from . import Transaction


class TransactionVerifier(BaseTransactionVerifier):
    _hash_salt = HASH_SALT

    def __init__(self, hash_generator_version: int):
        super().__init__(hash_generator_version)
        self._tx_serializer = TransactionSerializer(hash_generator_version)

    def verify(self, tx: 'Transaction', blockchain=None):
        self.verify_loosely(tx, blockchain)

    def verify_loosely(self, tx: 'Transaction', blockchain=None):
        self.verify_hash(tx)
        self.verify_data(tx)
        if blockchain:
            self.verify_nid(tx, blockchain)
            self.verify_tx_hash_unique(tx, blockchain)

    def verify_signature(self, tx: 'Transaction'):
        pass

    def verify_data(self, tx: 'Transaction'):
        if tx.data_type != "issue":
            raise RuntimeError(f"tx{tx}\n"
                               f"data_type {tx.data_type}")

    def verify_nid(self, tx: 'Transaction', blockchain):
        nid = blockchain.find_nid()
        if hex(tx.nid) != nid:
            raise RuntimeError(f"tx({tx})\n"
                               f"nid {hex(tx.nid)} != {nid} not match.")
