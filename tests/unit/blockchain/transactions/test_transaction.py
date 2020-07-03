import pytest

from loopchain.blockchain.transactions import Transaction, TransactionVersioner
from loopchain.blockchain.transactions import genesis, v2, v3
from tests.unit.blockchain.conftest import TxFactory


@pytest.mark.parametrize("tx_version", [genesis.version, v2.version, v3.version])
class TestTransactions:
    def test_type_is_none(self, tx_factory: TxFactory, tx_version: str):
        tx = tx_factory(tx_version)

        assert not tx.type()

    def test_size_attribute_has_set_correctly(self, tx_factory: TxFactory, tx_version: str):
        from loopchain.blockchain.transactions.transaction import _size_attr_name_

        print("tx_fac:", tx_factory)
        tx = tx_factory(tx_version)
        assert not hasattr(tx, _size_attr_name_)

        tx.size(versioner=TransactionVersioner())
        assert getattr(tx, _size_attr_name_)

    def test_is_signed(self, tx_factory: TxFactory, tx_version: str):
        tx: Transaction = tx_factory(tx_version)

        if tx_version == genesis.version:
            pass
        else:
            assert tx.is_signed()

    def test_signer_address(self, tx_factory: TxFactory, tx_version: str):
        tx: Transaction = tx_factory(tx_version)

        if tx_version == genesis.version:
            with pytest.raises(NotImplementedError):
                assert tx.signer_address
        else:
            assert tx.signer_address
