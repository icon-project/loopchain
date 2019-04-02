from loopchain.blockchain.types import MalformedStr
from loopchain.blockchain.transactions import TransactionVerifier as BaseTransactionVerifier
from loopchain.blockchain.transactions.v2 import Transaction, TransactionSerializer, HASH_SALT


class TransactionVerifier(BaseTransactionVerifier):
    _hash_salt = HASH_SALT

    def __init__(self, hash_generator_version: int):
        super().__init__(hash_generator_version)
        self._tx_serializer = TransactionSerializer(hash_generator_version)

    def verify(self, tx: 'Transaction', blockchain=None):
        if isinstance(tx.from_address, MalformedStr):
            raise RuntimeError(f"Tx({tx})\n"
                               f"To Address({tx.from_address} is malformed.")

        if isinstance(tx.to_address, MalformedStr):
            raise RuntimeError(f"Tx({tx})\n"
                               f"To Address({tx.to_address} is malformed.")

        if isinstance(tx.value, MalformedStr):
            raise RuntimeError(f"Tx({tx})\n"
                               f"Value({tx.value} is malformed.")

        if isinstance(tx.fee, MalformedStr):
            raise RuntimeError(f"Tx({tx})\n"
                               f"Fee({tx.fee} is malformed.")

        if isinstance(tx.nonce, MalformedStr):
            raise RuntimeError(f"Tx({tx})\n"
                               f"Nonce({tx.fee} is malformed.")

        if tx.extra:
            raise RuntimeError(f"Tx({tx})\n"
                               f"Unexpected params {tx.extra}.")

        self.verify_loosely(tx, blockchain)

    def verify_loosely(self, tx: 'Transaction', blockchain=None):
        self.verify_hash(tx)
        self.verify_signature(tx)
        if blockchain:
            self.verify_tx_hash_unique(tx, blockchain)
