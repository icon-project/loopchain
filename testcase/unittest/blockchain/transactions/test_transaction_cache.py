import os
import random

import pytest

from loopchain.blockchain.exception import TransactionInvalidHashError
from loopchain.blockchain.exception import TransactionInvalidSignatureError
from loopchain.blockchain.transactions import TransactionBuilder
from loopchain.blockchain.transactions import TransactionVerifier
from loopchain.blockchain.transactions import TransactionVersioner
from loopchain.blockchain.types import ExternalAddress
from loopchain.blockchain.types import Hash32
from loopchain.blockchain.types import Signature
from loopchain.crypto.signature import Signer

tx_versioner = TransactionVersioner()


class TestTxCache:
    target_attrs = ["hash", "signature"]

    @pytest.fixture
    def tx(self):
        """Transaction fixture"""
        tb = TransactionBuilder.new(version="0x3", type_=None, versioner=tx_versioner)
        tb.step_limit = 1000000
        tb.value = 100000
        tb.signer = Signer.from_prikey(os.urandom(32))
        tb.to_address = ExternalAddress(os.urandom(20))
        tb.nid = 3
        tb.nonce = random.randint(0, 100000)
        tb.data = "test"
        tb.data_type = "message"

        transaction = tb.build()

        return transaction

    @pytest.mark.parametrize("target_attr", target_attrs)
    def test_no_cache_attr_in_tx_if_not_verified(self, tx, target_attr):
        """Check that Transaction has no attribute until the verification func has been invoked"""
        if "cache" in dir(tx):
            raise AttributeError("Something wrong. Transaction has cached value when initialized.")

        with pytest.raises(AttributeError):
            getattr(tx, f"_cache_verify_{target_attr}")

    @pytest.mark.parametrize("raise_exception", [True, False])
    @pytest.mark.parametrize("target_attr", ["hash", "signature"])
    def test_has_cache_attr_when_verified_successfully(self, tx, raise_exception, target_attr):
        """Check that the verification result has been cached successfully"""
        tv = TransactionVerifier.new(tx.version,  tx.type(), tx_versioner, raise_exceptions=raise_exception)

        verify_func_name = f"verify_{target_attr}"
        verify_func = getattr(tv, verify_func_name)
        verify_func(tx)

        assert getattr(tx, f"_cache_{verify_func_name}")

    @pytest.mark.parametrize("raise_exception", [True, False])
    @pytest.mark.parametrize("expected_exc, target_attr, fake_value", [
        (TransactionInvalidHashError, "hash", Hash32.new()),
        (TransactionInvalidSignatureError, "signature", Signature.new()),
    ])
    def test_exception_cached_when_raised_exception_while_verification(self, tx, raise_exception, expected_exc, target_attr, fake_value, monkeypatch):
        """Check that the exception successfully cached when raised any exception while verification step"""
        tv = TransactionVerifier.new(tx.version,  tx.type(), tx_versioner, raise_exceptions=raise_exception)
        verify_func = getattr(tv, f"verify_{target_attr}")

        orig_value = getattr(tx, target_attr)
        test_values = (fake_value, orig_value)

        for test_value in test_values:
            # Monkeypatch
            object.__setattr__(tx, target_attr, test_value)
            assert getattr(tx, target_attr) == test_value

            # Verification test
            if raise_exception:
                with pytest.raises(expected_exc):
                    verify_func(tx)
            else:
                tv.exceptions.clear()
                assert not tv.exceptions
                verify_func(tx)
                assert isinstance(tv.exceptions[0], expected_exc)

    @pytest.mark.parametrize("raise_exception", [True, False])
    @pytest.mark.parametrize("expected_exc, target_attr, fake_value", [
        (TransactionInvalidHashError, "hash", Hash32.new()),
        (TransactionInvalidSignatureError, "signature", Signature.new()),
    ])
    def test_verify_success_and_no_exc_with_fake_value_at_second(self, tx, raise_exception, expected_exc, target_attr, fake_value, monkeypatch):
        """Check that the result is successfully cached and bypasses further verifications which could raise exceptions.

        Do not apply this usecase in code!
        This test aims the reliablity of cache logic, not for the usefulness of this case.
        """
        tv = TransactionVerifier.new(tx.version,  tx.type(), tx_versioner, raise_exceptions=raise_exception)
        verify_func = getattr(tv, f"verify_{target_attr}")

        # First verification
        verify_func(tx)

        # Monkeypatch with fake value
        object.__setattr__(tx, target_attr, fake_value)
        assert getattr(tx, target_attr) == fake_value

        # Verify again with fake value and ensure no exceptions raised
        if raise_exception:
            verify_func(tx)
        else:
            tv.exceptions.clear()
            assert not tv.exceptions
            verify_func(tx)
            assert not tv.exceptions

    @pytest.mark.parametrize("tag", ["first", "second"])
    @pytest.mark.parametrize("target_attr", ["hash", "signature"])
    def test_benchmark_verify(self, benchmark, tx, target_attr, tag):
        """Benchmark the elapsed time of verification func in various cases."""
        tv = TransactionVerifier.new(tx.version,  tx.type(), tx_versioner)
        verify_func = getattr(tv, f"verify_{target_attr}")

        if tag == "first":
            benchmark(verify_func, tx)
        else:
            verify_func(tx)
            benchmark(verify_func, tx)

