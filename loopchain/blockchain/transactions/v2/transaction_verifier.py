from typing import TYPE_CHECKING
from . import TransactionSerializer, HASH_SALT
from .. import TransactionVerifier as BaseTransactionVerifier
from ... import MalformedStr

if TYPE_CHECKING:
    from . import Transaction


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

        self.verify_loosely(tx, blockchain)

    def verify_loosely(self, tx: 'Transaction', blockchain=None):
        self.verify_hash(tx)
        self.verify_signature(tx)
        if blockchain:
            self.verify_tx_hash_unique(tx, blockchain)
