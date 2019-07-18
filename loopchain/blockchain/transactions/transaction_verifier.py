from abc import ABC, abstractmethod
from typing import TYPE_CHECKING
from loopchain.crypto.signature import SignVerifier
from loopchain.crypto.hashing import build_hash_generator
from loopchain.blockchain.exception import TransactionDuplicatedHashError, TransactionInvalidHashError
from loopchain.blockchain.exception import TransactionInvalidSignatureError


if TYPE_CHECKING:
    from loopchain.blockchain.transactions import Transaction, TransactionVersioner


class TransactionVerifier(ABC):
    _hash_salt = None
    _allow_unsigned = False

    def __init__(self, hash_generator_version: int, raise_exceptions=True):
        self.exceptions = []

        self._hash_generator = build_hash_generator(hash_generator_version, self._hash_salt)
        self._tx_serializer = None
        self._raise_exceptions = raise_exceptions

    @abstractmethod
    def pre_verify(self, tx: 'Transaction', **kwargs):
        raise NotImplementedError

    @abstractmethod
    def verify(self, tx: 'Transaction', blockchain=None):
        raise NotImplementedError

    @abstractmethod
    def verify_loosely(self, tx: 'Transaction', blockchain=None):
        raise NotImplementedError

    def verify_tx_hash_unique(self, tx: 'Transaction', blockchain):
        if blockchain.find_tx_by_key(tx.hash.hex()):
            exception = TransactionDuplicatedHashError(tx)
            self._handle_exceptions(exception)

    def verify_hash(self, tx: 'Transaction'):
        params = self._tx_serializer.to_origin_data(tx)
        tx_hash_expected = self._hash_generator.generate_hash(params)
        if tx_hash_expected != tx.hash:
            exception = TransactionInvalidHashError(tx, tx_hash_expected)
            self._handle_exceptions(exception)

    def verify_signature(self, tx: 'Transaction'):
        if self._allow_unsigned and not tx.is_signed():
            return

        sign_verifier = SignVerifier.from_address(tx.signer_address.hex_xx())
        try:
            sign_verifier.verify_hash(tx.hash, tx.signature)
        except Exception as e:
            exception = TransactionInvalidSignatureError(tx, message=str(e))
            self._handle_exceptions(exception)

    def _handle_exceptions(self, exception: Exception):
        if self._raise_exceptions:
            raise exception
        else:
            self.exceptions.append(exception)

    @classmethod
    def new(cls, version: str, type_: str, versioner: 'TransactionVersioner', raise_exceptions=True):
        hash_generator_version = versioner.get_hash_generator_version(version)

        from . import v3_issue
        if version == v3_issue.version and type_ == "issue":
            return v3_issue.TransactionVerifier(hash_generator_version)

        from . import v3
        if version == v3.version:
            return v3.TransactionVerifier(hash_generator_version, raise_exceptions)

        from . import v2
        if version == v2.version:
            return v2.TransactionVerifier(hash_generator_version, raise_exceptions)

        from . import genesis
        if version == genesis.version:
            return genesis.TransactionVerifier(hash_generator_version, raise_exceptions)

        raise RuntimeError(f"Not supported tx version({version})")
