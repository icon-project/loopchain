import functools
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from legacy.blockchain.exception import TransactionDuplicatedHashError, TransactionInvalidHashError
from legacy.blockchain.exception import TransactionInvalidSignatureError
from legacy.crypto.hashing import build_hash_generator
from legacy.crypto.signature import SignVerifier

if TYPE_CHECKING:
    from legacy.blockchain.transactions import Transaction, TransactionVersioner


def cache_result(tv_func):
    """Cache verified result to Transaction.

    If Transaction verified successfully, cache its result.
    If Transaction verified failed with exception, cache its exception.
    If Transaction didn't verified at all, its attribute may not exist.
    """
    @functools.wraps(tv_func)
    def _wrapper(*args, **kwargs):
        tv: TransactionVerifier = args[0]
        tx: Transaction = args[1]

        attr_name = "_cache_" + tv_func.__name__
        cached_result = getattr(tx, attr_name, False)

        if isinstance(cached_result, Exception):
            tv._handle_exceptions(cached_result)
            return
        elif cached_result:
            return

        if tv._raise_exceptions:
            try:
                tv_func(*args, **kwargs)
            except Exception as e:
                object.__setattr__(tx, attr_name, e)
                raise
            else:
                object.__setattr__(tx, attr_name, True)
        else:
            orig_exceptions = set(tv.exceptions)
            tv_func(*args, **kwargs)
            if len(orig_exceptions) != len(tv.exceptions):
                exceptions = set(tv.exceptions) - orig_exceptions
                object.__setattr__(tx, attr_name, next(iter(exceptions)))
            else:
                object.__setattr__(tx, attr_name, True)

    return _wrapper


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

    @cache_result
    def verify_hash(self, tx: 'Transaction'):
        params = self._tx_serializer.to_origin_data(tx)
        tx_hash_expected = self._hash_generator.generate_hash(params)
        if tx_hash_expected != tx.hash:
            exception = TransactionInvalidHashError(tx, tx_hash_expected)
            self._handle_exceptions(exception)

    @cache_result
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
        if version == v3_issue.version and type_ == "base":
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
