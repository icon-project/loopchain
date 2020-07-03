import os

import pytest

from loopchain.blockchain.transactions import TransactionBuilder
from loopchain.blockchain.transactions import genesis, v2, v3
from loopchain.blockchain.types import Hash32, Signature, ExternalAddress
from loopchain.crypto.signature import Signer
from tests.unit.blockchain.conftest import TxFactory, TxBuilderFactory


@pytest.mark.parametrize("tx_version", [genesis.version, v2.version, v3.version])
class TestTransactionBuilderBase:
    def test_builder_version_check(self, tx_builder_factory: TxBuilderFactory, tx_version):
        tx_builder = tx_builder_factory(tx_version)

        if tx_version == genesis.version:
            assert isinstance(tx_builder, genesis.TransactionBuilder)
        elif tx_version == v2.version:
            assert isinstance(tx_builder, v2.TransactionBuilder)
        elif tx_version == v3.version:
            assert isinstance(tx_builder, v3.TransactionBuilder)

    def test_reset_cache_resets_members(self, tx_builder_factory: TxBuilderFactory, tx_version):
        tx_builder = tx_builder_factory(tx_version)
        tx_builder.from_address = tx_builder.from_address or "aa"
        tx_builder.hash = tx_builder.hash or "aa"
        tx_builder.signature = tx_builder.signature or "aa"
        tx_builder.origin_data = tx_builder.origin_data or "aa"
        tx_builder.raw_data = tx_builder.raw_data or ""

        tx_builder.reset_cache()
        assert not tx_builder.from_address
        assert not tx_builder.hash
        assert not tx_builder.signature
        assert not tx_builder.origin_data
        assert not tx_builder.raw_data

        if tx_version == genesis.version:
            assert not tx_builder.nid_generated
        elif tx_version == v2.version:
            assert not tx_builder._timestamp
        elif tx_version == v3.version:
            assert not tx_builder._timestamp

    def test_from_address_returns_its_addr_if_exists(self, tx_builder_factory: TxBuilderFactory, tx_version):
        tx_builder = tx_builder_factory(tx_version)
        expected_addr = ExternalAddress(os.urandom(ExternalAddress.size))

        tx_builder.from_address = expected_addr
        built_addr = tx_builder.build_from_address()

        assert expected_addr == built_addr

    def test_from_address_raise_exc_if_no_from_addr_and_no_signer(self, tx_builder_factory: TxBuilderFactory, tx_version):
        tx_builder = tx_builder_factory(tx_version)
        tx_builder.reset_cache()
        tx_builder.signer = None

        with pytest.raises(RuntimeError):
            assert tx_builder.build_from_address()

    def test_from_address_generate_addr_if_no_from_addr_but_signer(self, tx_builder_factory: TxBuilderFactory, tx_version):
        tx_builder = tx_builder_factory(tx_version)
        tx_builder.reset_cache()

        assert not tx_builder.from_address
        assert tx_builder.signer

        assert tx_builder.build_from_address()

    def test_build_origin_data(self, tx_builder_factory: TxBuilderFactory, tx_version):
        tx_builder = tx_builder_factory(tx_version)
        tx_builder.build_from_address()
        origin_data = tx_builder.build_origin_data()

        assert origin_data

    def test_build_hash_returns_valid_hash_form(self, tx_builder_factory: TxBuilderFactory, tx_version):
        tx_builder: TransactionBuilder = tx_builder_factory(tx_version)
        tx_builder.build_from_address()
        tx_builder.build_origin_data()
        hash_ = tx_builder.build_hash()

        assert isinstance(hash_, Hash32)

    def test_build_hash_fails_if_origin_data_is_not_exist(self, tx_builder_factory: TxBuilderFactory, tx_version):
        tx_builder = tx_builder_factory(tx_version)
        assert tx_builder.origin_data is None

        with pytest.raises(RuntimeError, match="origin data is required"):
            assert tx_builder.build_hash()

    def test_sign_builds_signature_and_hash(self, tx_builder_factory: TxBuilderFactory, tx_version, mocker):
        tx_builder: TransactionBuilder = tx_builder_factory(tx_version)
        assert not tx_builder.signature
        assert not tx_builder.hash

        tx_builder.build_from_address()
        tx_builder.build_origin_data()

        mocker.patch.object(Signer, "sign_hash", return_value=os.urandom(Signature.size))
        tx_builder.sign()
        assert isinstance(tx_builder.signature, Signature)
        assert tx_builder.hash

    def test_build_raw_data(self, tx_builder_factory: TxBuilderFactory, tx_version):
        tx_builder = tx_builder_factory(tx_version)

        tx_builder.build_from_address()
        tx_builder.build_origin_data()
        tx_builder.build_hash()
        tx_builder.sign()
        raw_data = tx_builder.build_raw_data()

        assert raw_data

    def test_build_transaction(self, tx_builder_factory: TxBuilderFactory, tx_version):
        tx_builder = tx_builder_factory(tx_version)
        tx = tx_builder.build()

        if tx_version == genesis.version:
            assert isinstance(tx, genesis.Transaction)
        elif tx_version == v2.version:
            assert isinstance(tx, v2.Transaction)
        elif tx_version == v3.version:
            assert isinstance(tx, v3.Transaction)

    def test_sign_transaction(self, tx_builder_factory: TxBuilderFactory, tx_version):
        tx_builder = tx_builder_factory(tx_version)
        tx = tx_builder.build()

        if tx_version == genesis.version:
            with pytest.raises(NotImplementedError):
                tx_builder.sign_transaction(tx)
        else:
            tx_builder.sign_transaction(tx)

    def test_sign_transaction_raises_exc_if_signer_addr_ne_tx_signer_addr(self, tx_builder_factory: TxBuilderFactory, tx_version):
        tx_builder = tx_builder_factory(tx_version)
        tx = tx_builder.build()

        tx_builder.signer = Signer.new()

        if tx_version == genesis.version:
            with pytest.raises(NotImplementedError):
                tx_builder.sign_transaction(tx)
        else:
            with pytest.raises(RuntimeError, match="Signer not match"):
                tx_builder.sign_transaction(tx)


class TestTransactionBuilder_genesis:
    def test_build_nid_raises_exc_if_hash_not_exists(self, tx_builder_factory: TxBuilderFactory):
        tx_builder: genesis.TransactionBuilder = tx_builder_factory(genesis.version)
        tx_builder.reset_cache()

        with pytest.raises(RuntimeError):
            assert tx_builder.build_nid()

    def test_build_nid_returns_its_nid_if_exists(self, tx_builder_factory: TxBuilderFactory):
        tx_builder: genesis.TransactionBuilder = tx_builder_factory(genesis.version)
        expected_nid = genesis.NID.unknown
        tx_builder.nid = expected_nid
        tx_builder.build_origin_data()
        tx_builder.build_hash()
        nid_generated = tx_builder.build_nid()

        assert expected_nid == nid_generated

    @pytest.mark.parametrize("tx_hash, expected_nid", [
        ("0x5aa2453a84ba2fb1e3394b9e3471f5dcebc6225fc311a97ca505728153b9d246", genesis.NID.mainnet),
        ("0x5a7ce1e10a6fd5fb3925a011528f89a5debfead2405f5545a99d1a1310e48c9e", genesis.NID.testnet)
    ])
    def test_build_nid_with_specific_hash_matches_expected_nid(self, tx_builder_factory: TxBuilderFactory, tx_hash, expected_nid: genesis.NID):
        tx_builder: genesis.TransactionBuilder = tx_builder_factory(genesis.version)
        assert not tx_builder.nid

        tx_builder.hash = Hash32.fromhex(tx_hash)
        nid_generated = tx_builder.build_nid()

        assert nid_generated == expected_nid
