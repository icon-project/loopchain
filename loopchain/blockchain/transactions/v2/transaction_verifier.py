from typing import TYPE_CHECKING
from . import TransactionSerializer, HASH_SALT
from .. import TransactionVerifier as BaseTransactionVerifier
from ... import MalformedAddress

if TYPE_CHECKING:
    from . import Transaction


class TransactionVerifier(BaseTransactionVerifier):
    _hash_salt = HASH_SALT

    def __init__(self, hash_generator_version: int):
        super().__init__(hash_generator_version)
        self._tx_serializer = TransactionSerializer(hash_generator_version)

    def verify(self, tx: 'Transaction', blockchain=None):
        if isinstance(tx.to_address, MalformedAddress):
            raise RuntimeError(f"Tx({tx.hash}), "
                               f"To Address({tx.to_address.hex_xx()} is malformed.")

        if isinstance(tx.from_address, MalformedAddress):
            raise RuntimeError(f"Tx({tx.hash}), "
                               f"To Address({tx.from_address.hex_xx()} is malformed.")

        self.verify_loosely(tx, blockchain)

    def verify_loosely(self, tx: 'Transaction', blockchain=None):
        self.verify_hash(tx)
        self.verify_signature(tx)
        if blockchain:
            self.verify_tx_hash_unique(tx, blockchain)