import pytest

from loopchain.blockchain.transactions import TransactionVersioner
from loopchain.blockchain.transactions import genesis, v2, v3

TX_DATA = {
    genesis.version: {
        "nid": "0x3",
        "accounts": [
            {
                "name": "god",
                "address": "hx5a05b58a25a1e5ea0f1d5715e1f655dffc1fb30a",
                "balance": "0x2961fd42d71041700b90000"
            }
        ]
    },
    v2.version: {
        "scheme": "v2_tx_data_has_no_version_key"
    },
    v3.version: {
        "version": "0x3",
        "dataType": "call"
    }
}


class TestTransactionVersioner:
    @pytest.fixture
    def tx_versioner(self) -> TransactionVersioner:
        return TransactionVersioner()

    @pytest.mark.parametrize("expected_version", [genesis.version, v2.version, v3.version])
    def test_get_version_returns_matched_version(self, tx_versioner, expected_version):
        tx_data = TX_DATA[expected_version]
        version, type_ = tx_versioner.get_version(tx_data=tx_data)

        assert version == expected_version

    @pytest.mark.parametrize("expected_version", [genesis.version, v2.version, v3.version])
    def test_get_hash_generator_version(self, tx_versioner, expected_version):
        version = tx_versioner.get_hash_generator_version(expected_version)

        assert version == 1
