import os

import pytest

from loopchain.blockchain.blockchain import BlockChain
from loopchain.blockchain.exception import TransactionDuplicatedHashError, TransactionInvalidHashError
from loopchain.blockchain.transactions import Transaction, TransactionVerifier, TransactionVersioner, TransactionBuilder
from loopchain.blockchain.transactions import genesis, v2, v3
from loopchain.blockchain.types import Hash32
from tests.unit.blockchain.conftest import TxFactory, TxBuilderFactory

tx_versioner = TransactionVersioner()


@pytest.mark.parametrize("tx_version", [genesis.version, v2.version, v3.version])
class TestTransactionVerifierBase:
    @pytest.fixture(autouse=True)
    def auto_fixture_for_test_abc_verifier(self, mocker):
        mocker.patch.object(TransactionVerifier, "__abstractmethods__", new_callable=set)

    def test_verifier_version_check(self, tx_version, tx_factory: TxFactory):
        tx: Transaction = tx_factory(tx_version)
        tv = TransactionVerifier.new(version=tx.version, type_=tx.type(), versioner=tx_versioner)

        if tx_version == genesis.version:
            assert isinstance(tv, genesis.TransactionVerifier)
        elif tx_version == v2.version:
            assert isinstance(tv, v2.TransactionVerifier)
        elif tx_version == v3.version:
            assert isinstance(tv, v3.TransactionVerifier)

    def test_verify_tx_hash_unique(self, tx_version, tx_factory: TxFactory, mocker):
        tx: Transaction = tx_factory(tx_version)
        tv = TransactionVerifier.new(version=tx.version, type_=tx.type(), versioner=tx_versioner)

        mock_blockchain: BlockChain = mocker.MagicMock(spec=BlockChain)
        mock_blockchain.find_tx_by_key.return_value = None  # Not found in db, which means the tx is unique.

        tv.verify_tx_hash_unique(tx, mock_blockchain)

    @pytest.mark.parametrize("raise_exc", [True, False])
    def test_verify_tx_hash_unique_but_duplicated_tx(self, tx_version, tx_factory: TxFactory, mocker, raise_exc):
        tx: Transaction = tx_factory(tx_version)
        tv = TransactionVerifier.new(version=tx.version, type_=tx.type(), versioner=tx_versioner, raise_exceptions=raise_exc)

        mock_blockchain: BlockChain = mocker.MagicMock(spec=BlockChain)
        mock_blockchain.find_tx_by_key.return_value = "tx_info_found!"

        if raise_exc:
            with pytest.raises(TransactionDuplicatedHashError):
                tv.verify_tx_hash_unique(tx, mock_blockchain)
        else:
            assert not tv.exceptions
            tv.verify_tx_hash_unique(tx, mock_blockchain)

            with pytest.raises(TransactionDuplicatedHashError):
                raise tv.exceptions[0]

    def test_verify_signature(self, tx_version, tx_factory: TxFactory):
        tx: Transaction = tx_factory(tx_version)
        tv = TransactionVerifier.new(version=tx.version, type_=tx.type(), versioner=tx_versioner)

        if tx_version != genesis.version:
            assert tx.hash
            assert tx.signature

            tv.verify_signature(tx)


@pytest.mark.xfail(reason="This test is branched because the raw_data of genesis tx has signature")
class TestTransactionVerifierHash_genesis:
    tx_version = genesis.version

    def test_verify_hash(self, tx_builder_factory: TxBuilderFactory):
        tx_builder: TransactionBuilder = tx_builder_factory(self.tx_version)
        tx: Transaction = tx_builder.build(is_signing=False)

        tv = TransactionVerifier.new(version=tx.version, type_=tx.type(), versioner=tx_versioner)

        tv.verify_hash(tx)

    @pytest.mark.parametrize("raise_exc", [True, False])
    def test_verify_hash_with_invalid_hash(self, tx_builder_factory: TxBuilderFactory, raise_exc):
        tx_builder: TransactionBuilder = tx_builder_factory(self.tx_version)
        tx: Transaction = tx_builder.build(is_signing=False)
        object.__setattr__(tx, "hash", Hash32(os.urandom(Hash32.size)))

        tv = TransactionVerifier.new(version=tx.version, type_=tx.type(), versioner=tx_versioner, raise_exceptions=raise_exc)

        if raise_exc:
            with pytest.raises(TransactionInvalidHashError):
                tv.verify_hash(tx)
        else:
            assert not tv.exceptions
            tv.verify_hash(tx)

            with pytest.raises(TransactionInvalidHashError):
                raise tv.exceptions[0]


@pytest.mark.xfail(reason="This test is branched because the raw_data of genesis tx has signature")
@pytest.mark.parametrize("tx_version", [v2.version, v3.version])
class TestTransactionVerifierHash_vv:
    def test_verify_hash(self, tx_version, tx_factory: TxFactory):
        tx: Transaction = tx_factory(tx_version)
        tv = TransactionVerifier.new(version=tx.version, type_=tx.type(), versioner=tx_versioner)

        tv.verify_hash(tx)

    @pytest.mark.parametrize("raise_exc", [True, False])
    def test_verify_hash_with_invalid_hash(self, tx_version, tx_builder_factory: TxBuilderFactory, raise_exc):
        tx_builder: TransactionBuilder = tx_builder_factory(tx_version)
        tx: Transaction = tx_builder.build()
        object.__setattr__(tx, "hash", Hash32(os.urandom(Hash32.size)))

        tv = TransactionVerifier.new(version=tx.version, type_=tx.type(), versioner=tx_versioner, raise_exceptions=raise_exc)

        if raise_exc:
            with pytest.raises(TransactionInvalidHashError):
                tv.verify_hash(tx)
        else:
            assert not tv.exceptions
            tv.verify_hash(tx)

            with pytest.raises(TransactionInvalidHashError):
                raise tv.exceptions[0]
