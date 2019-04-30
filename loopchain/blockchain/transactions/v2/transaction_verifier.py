from typing import TYPE_CHECKING
from . import TransactionSerializer, HASH_SALT
from .. import TransactionVerifier as BaseTransactionVerifier
from ... import MalformedStr

if TYPE_CHECKING:
    from . import Transaction


class TransactionVerifier(BaseTransactionVerifier):
    _hash_salt = HASH_SALT

    def __init__(self, hash_generator_version: int, raise_exceptions=True):
        super().__init__(hash_generator_version, raise_exceptions)
        self._tx_serializer = TransactionSerializer(hash_generator_version)

    def verify(self, tx: 'Transaction', blockchain=None):
        if isinstance(tx.from_address, MalformedStr):
            exception = RuntimeError(f"Tx({tx})\n"
                                     f"To Address({tx.from_address} is malformed.")
            self._handle_exceptions(exception)

        if isinstance(tx.to_address, MalformedStr):
            exception = RuntimeError(f"Tx({tx})\n"
                                     f"To Address({tx.to_address} is malformed.")
            self._handle_exceptions(exception)

        if isinstance(tx.value, MalformedStr):
            exception = RuntimeError(f"Tx({tx})\n"
                                     f"Value({tx.value} is malformed.")
            self._handle_exceptions(exception)

        if isinstance(tx.fee, MalformedStr):
            exception = RuntimeError(f"Tx({tx})\n"
                                     f"Fee({tx.fee} is malformed.")
            self._handle_exceptions(exception)

        if isinstance(tx.nonce, MalformedStr):
            exception = RuntimeError(f"Tx({tx})\n"
                                     f"Nonce({tx.fee} is malformed.")
            self._handle_exceptions(exception)

        if tx.extra:
            exception = RuntimeError(f"Tx({tx})\n"
                                     f"Unexpected params {tx.extra}.")
            self._handle_exceptions(exception)

        self.verify_loosely(tx, blockchain)

    def verify_loosely(self, tx: 'Transaction', blockchain=None):
        self.verify_hash(tx)
        self.verify_signature(tx)
        if blockchain:
            self.verify_tx_hash_unique(tx, blockchain)
