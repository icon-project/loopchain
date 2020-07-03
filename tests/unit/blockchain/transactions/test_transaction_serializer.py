import pytest
from freezegun import freeze_time

from loopchain.blockchain.transactions import TransactionSerializer, TransactionVersioner, Transaction
from loopchain.blockchain.transactions import genesis, v2, v3, v3_issue
from loopchain.blockchain.types import Hash32
from tests.unit.blockchain.conftest import TxFactory, TxBuilderFactory

tx_versioner = TransactionVersioner()


class TestTransactionSerializerBase:
    @pytest.mark.parametrize("tx_version", [genesis.version, v2.version, v3.version])
    def test_serializer_version_check(self, tx_factory: TxFactory, tx_version):
        tx: Transaction = tx_factory(tx_version)
        ts = TransactionSerializer.new(version=tx.version, type_=tx.type(), versioner=tx_versioner)

        if tx_version == genesis.version:
            assert isinstance(ts, genesis.TransactionSerializer)
        elif tx_version == v2.version:
            assert isinstance(ts, v2.TransactionSerializer)
        elif tx_version == v3.version:
            assert isinstance(ts, v3.TransactionSerializer)
        else:
            assert False

    @pytest.mark.xfail(reason="Genesis origin data has no NID?")
    @pytest.mark.parametrize("tx_version, expected_keys", [
        (genesis.version, ["accounts", "message", "signature"]),
        (v2.version, ["from", "to", "value", "fee", "timestamp", "nonce"]),
        (v3.version, ["version", "from", "to", "stepLimit", "timestamp", "nid", "value", "nonce"])
    ])
    def test_to_origin_data_has_valid_form(self, tx_factory: TxFactory, tx_version, expected_keys):
        tx: Transaction = tx_factory(tx_version)
        ts = TransactionSerializer.new(version=tx.version, type_=tx.type(), versioner=tx_versioner)

        origin_data = ts.to_origin_data(tx)
        assert set(origin_data) == set(expected_keys)


class TestTransactionSerializer_genesis:
    tx_version = genesis.version

    # TODO: What is diffrence between tx.raw_data and its dict casted?
    def test_to_raw_data_equals_tx_raw_data(self, tx_factory: TxFactory):
        tx: Transaction = tx_factory(self.tx_version)
        ts = TransactionSerializer.new(version=tx.version, type_=tx.type(), versioner=tx_versioner)

        raw_data = ts.to_raw_data(tx)
        assert raw_data == tx.raw_data

    def test_to_db_data_equals_tx_raw_data(self, tx_factory: TxFactory):
        tx: Transaction = tx_factory(self.tx_version)
        ts = TransactionSerializer.new(version=tx.version, type_=tx.type(), versioner=tx_versioner)

        db_data = ts.to_db_data(tx)
        assert db_data == tx.raw_data

    def test_to_full_data_equals_tx_raw_data(self, tx_factory: TxFactory):
        tx: Transaction = tx_factory(self.tx_version)
        ts = TransactionSerializer.new(version=tx.version, type_=tx.type(), versioner=tx_versioner)

        full_data = ts.to_full_data(tx)
        assert full_data == tx.raw_data

    @pytest.mark.xfail(reason="Check `is_signing` flag at build().")
    def test_orig_tx_equals_deserialized_tx(self, tx_builder_factory: TxBuilderFactory):
        with freeze_time():
            # TODO: origin data contains signature, so it affects tx_hash of deserialized tx.
            tx: genesis.Transaction = tx_builder_factory(self.tx_version)\
                .build(is_signing=False)
            ts: genesis.TransactionSerializer = TransactionSerializer.new(version=tx.version, type_=tx.type(), versioner=tx_versioner)

        tx_restored = ts.from_(tx.raw_data)

        assert tx == tx_restored

    @pytest.mark.xfail(raises=KeyError, reason="Genesis tx raw_data has no `tx_hash`?")
    def test_get_hash(self, tx_factory: TxFactory):
        tx: Transaction = tx_factory(self.tx_version)
        ts = TransactionSerializer.new(version=tx.version, type_=tx.type(), versioner=tx_versioner)

        full_data = ts.to_full_data(tx)
        tx_hash = ts.get_hash(full_data)

        assert tx.hash == Hash32(tx_hash)


class TestTransactionSerializer_v2:
    """
    tx_data = {
        "from": "hx63fac3fc777ad647d2c3a72cf0fc42d420a2ba81",
        "to": "hx5f8bfd603f1712ccd335d7648fbc989f63251354",
        "value": "0xde0b6b3a7640000",
        "fee": "0x2386f26fc10000",
        "nonce": "0x3",
        "tx_hash": "fabc1884932cf52f657475b6d62adcbce5661754ff1a9d50f13f0c49c7d48c0c",
        "signature": "cpSevyvPKC4OpAyywnoNyf0gamHylHOeuSPnLjkyILl1n9Xo4ygezzxda8LpcQ6K1rmo4JU+mXdh+Beh+/mhBgA=",
        "method": "icx_sendTransaction"
    }
    """
    tx_version = v2.version

    def test_to_raw_data_equals_dict_tx_raw_data(self, tx_factory: TxFactory):
        tx: Transaction = tx_factory(self.tx_version)
        ts = TransactionSerializer.new(version=tx.version, type_=tx.type(), versioner=tx_versioner)

        raw_data = ts.to_raw_data(tx)

        assert raw_data == tx.raw_data
        assert tx.raw_data == dict(tx.raw_data)

    def test_to_db_data_equals_full_data(self, tx_factory: TxFactory):
        tx: Transaction = tx_factory(self.tx_version)
        ts = TransactionSerializer.new(version=tx.version, type_=tx.type(), versioner=tx_versioner)

        db_data = ts.to_db_data(tx)
        full_data = ts.to_full_data(tx)

        assert db_data == full_data

    def test_to_full_data_equals_raw_data_with_method(self, tx_factory: TxFactory):
        tx: Transaction = tx_factory(self.tx_version)
        ts = TransactionSerializer.new(version=tx.version, type_=tx.type(), versioner=tx_versioner)

        full_data = ts.to_full_data(tx)
        raw_data = ts.to_raw_data(tx)
        raw_data["method"] = tx.method

        assert full_data == raw_data

    @pytest.mark.xfail(reason="Ignore `to_address (MalformedStr)` attrs ?")
    def test_orig_tx_equals_deserialized_tx(self, tx_factory: TxFactory):
        tx: Transaction = tx_factory(self.tx_version)
        ts = TransactionSerializer.new(version=tx.version, type_=tx.type(), versioner=tx_versioner)

        tx_restored = ts.from_(tx.raw_data)

        object.__setattr__(tx, "to_address", "")
        object.__setattr__(tx_restored, "to_address", "")

        assert tx == tx_restored

    def test_get_hash(self, tx_factory: TxFactory):
        tx: Transaction = tx_factory(self.tx_version)
        ts = TransactionSerializer.new(version=tx.version, type_=tx.type(), versioner=tx_versioner)

        tx_hash = ts.get_hash(tx.raw_data)
        assert tx.hash == Hash32.fromhex(tx_hash, ignore_prefix=True, allow_malformed=False)


class TestTransactionSerializer_v3:
    """
    tx_data = {
        "from": "hx5a05b58a25a1e5ea0f1d5715e1f655dffc1fb30a",
        "nid": "0x3",
        "nonce": "0x626c647430626f356d3369706f66637531687230",
        "signature": "MBRcb88rvnaSlDv8CC6+QUeajiDWwjRrE2i0klgNKCAkBYLnPGGBzhgbVgNKufJifeTAcpxNzDTCaVmHD7HDgwE=",
        "stepLimit": "0x50000000",
        "timestamp": "0x5908a356183ca",
        "to": "hx670e692ffd3d5587c36c3a9d8442f6d2a8fcc795",
        "value": "0x3328b944c4000",
        "version": "0x3",
        "txHash": "0x7b309fea7a1e1f760ff6b5c192875180c816e5680631d45e32f651321a833df4"
    }
    """

    tx_version = v3.version

    def test_to_raw_data_equals_dict_tx_raw_data(self, tx_factory: TxFactory):
        tx: Transaction = tx_factory(self.tx_version)
        ts = TransactionSerializer.new(version=tx.version, type_=tx.type(), versioner=tx_versioner)

        raw_data = ts.to_raw_data(tx)

        assert raw_data == tx.raw_data
        assert tx.raw_data == dict(tx.raw_data)

    def test_to_db_data_equals_dict_raw_data(self, tx_factory: TxFactory):
        tx: Transaction = tx_factory(self.tx_version)
        ts = TransactionSerializer.new(version=tx.version, type_=tx.type(), versioner=tx_versioner)

        db_data = ts.to_db_data(tx)

        assert db_data == tx.raw_data
        assert tx.raw_data == dict(tx.raw_data)

    def test_to_full_data_equals_to_db_data_with_tx_hash(self, tx_factory: TxFactory):
        tx: Transaction = tx_factory(self.tx_version)
        ts = TransactionSerializer.new(version=tx.version, type_=tx.type(), versioner=tx_versioner)

        full_data = ts.to_full_data(tx)
        db_data = ts.to_db_data(tx)
        db_data["txHash"] = tx.hash.hex()

        assert db_data == full_data

    def test_orig_tx_equals_deserialized_tx(self, tx_factory: TxFactory):
        tx: Transaction = tx_factory(self.tx_version)
        ts = TransactionSerializer.new(version=tx.version, type_=tx.type(), versioner=tx_versioner)

        full_data = ts.to_full_data(tx)
        tx_restored = ts.from_(full_data)

        assert tx == tx_restored

    def test_get_hash(self, tx_factory: TxFactory):
        tx: Transaction = tx_factory(self.tx_version)
        ts = TransactionSerializer.new(version=tx.version, type_=tx.type(), versioner=tx_versioner)

        full_data = ts.to_full_data(tx)
        tx_hash = ts.get_hash(full_data)

        assert tx.hash == Hash32.fromhex(tx_hash, ignore_prefix=True)


class TestTransactionSerializer_v3_issue:
    tx_version = v3_issue.version
    type_ = "base"

    def test_serializer_version_check(self, tx_factory: TxFactory):
        tx: Transaction = tx_factory(self.tx_version)
        ts = TransactionSerializer.new(version=tx.version, type_=self.type_, versioner=tx_versioner)

        assert isinstance(ts, v3_issue.TransactionSerializer)

    def test_to_origin_data_has_valid_form(self, tx_factory: TxFactory):
        tx: Transaction = tx_factory(self.tx_version)
        ts = TransactionSerializer.new(version=tx.version, type_=self.type_, versioner=tx_versioner)

        origin_data = ts.to_origin_data(tx)
        expected_keys = ["version", "from", "to", "stepLimit", "timestamp", "nid", "value", "nonce", "signature"]

        assert set(origin_data) == set(expected_keys)

    def test_to_raw_data_equals_dict_tx_raw_data(self, tx_factory: TxFactory):
        tx: Transaction = tx_factory(self.tx_version)
        ts = TransactionSerializer.new(version=tx.version, type_=self.type_, versioner=tx_versioner)

        raw_data = ts.to_raw_data(tx)

        assert raw_data == tx.raw_data
        assert tx.raw_data == dict(tx.raw_data)

    def test_to_db_data_equals_dict_raw_data(self, tx_factory: TxFactory):
        tx: Transaction = tx_factory(self.tx_version)
        ts = TransactionSerializer.new(version=tx.version, type_=self.type_, versioner=tx_versioner)

        db_data = ts.to_db_data(tx)

        assert db_data == tx.raw_data
        assert tx.raw_data == dict(tx.raw_data)

    def test_to_full_data_equals_to_db_data_with_tx_hash(self, tx_factory: TxFactory):
        tx: Transaction = tx_factory(self.tx_version)
        ts = TransactionSerializer.new(version=tx.version, type_=self.type_, versioner=tx_versioner)

        full_data = ts.to_full_data(tx)
        db_data = ts.to_db_data(tx)
        db_data["txHash"] = tx.hash.hex()

        assert db_data == full_data

    @pytest.mark.xfail(reason="How to test?")
    def test_orig_tx_equals_deserialized_tx(self, tx_factory: TxFactory):
        with freeze_time():
            tx: Transaction = tx_factory(self.tx_version)
            ts = TransactionSerializer.new(version=tx.version, type_=self.type_, versioner=tx_versioner)

        full_data = ts.to_full_data(tx)
        tx_restored = ts.from_(full_data)

        assert tx == tx_restored

    def test_get_hash(self, tx_factory: TxFactory):
        tx: Transaction = tx_factory(self.tx_version)
        ts = TransactionSerializer.new(version=tx.version, type_=self.type_, versioner=tx_versioner)

        full_data = ts.to_full_data(tx)
        tx_hash = ts.get_hash(full_data)

        assert tx.hash == Hash32.fromhex(tx_hash, ignore_prefix=True)
