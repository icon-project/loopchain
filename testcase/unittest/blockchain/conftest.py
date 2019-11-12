import functools
import os
from typing import List, Callable, Optional

import pytest

from loopchain.blockchain.transactions import Transaction, TransactionBuilder, TransactionVersioner
from loopchain.blockchain.transactions import genesis, v2, v3
from loopchain.blockchain.types import ExternalAddress, Address
from loopchain.crypto.signature import Signer

# ----- Type Hints
TxBuilderFactory = Callable[[str, Optional[str]], TransactionBuilder]
TxFactory = Callable[[str, Optional[str]], Transaction]


# ----- Global variables
def pytest_configure():
    signers = [Signer.from_prikey(os.urandom(32)) for _ in range(100)]
    reps = [ExternalAddress.fromhex_address(signer.address) for signer in signers]

    pytest.SIGNERS: List[Signer] = signers
    pytest.REPS: List[ExternalAddress] = reps


# ----- Transactions
@pytest.fixture
def tx_builder_factory() -> TxBuilderFactory:
    def add_attrs_to_genesis_builder(tx_builder):
        # Attributes that must be assigned
        tx_builder.accounts = [
            {
                "name": "god",
                "address": "hx54f7853dc6481b670caf69c5a27c7c8fe5be8269",
                "balance": "0x2961fff8ca4a62327800000"
            },
            {
                "name": "treasury",
                "address": "hx1000000000000000000000000000000000000000",
                "balance": "0x0"
            }
        ]
        tx_builder.message = (
            "A rhizome has no beginning or end; "
            "it is always in the middle, between things, interbeing, intermezzo. "
            "The tree is filiation, but the rhizome is alliance, uniquely alliance. "
            "The tree imposes the verb \"to be\" but the fabric of the rhizome is the conjunction, \"and ... and ...and...\""
            "This conjunction carries enough force to shake and uproot the verb \"to be.\" "
            "Where are you going? Where are you coming from? What are you heading for? "
            "These are totally useless questions.\n\n "
            "- Mille Plateaux, Gilles Deleuze & Felix Guattari\n\n\""
            "Hyperconnect the world\""
        )

        return tx_builder

    def add_attrs_to_v2_builder(tx_builder):
        # Attributes that must be assigned
        tx_builder.to_address = Address(os.urandom(Address.size))
        tx_builder.value: int = 10000
        tx_builder.fee: int = int(0.01 * 10**18)
        tx_builder.nonce: int = 10000

        return tx_builder

    def add_attrs_to_v3_builder(tx_builder):
        # Attributes that must be assigned
        tx_builder.to_address = ExternalAddress(os.urandom(ExternalAddress.size))
        tx_builder.value: int = 10000
        tx_builder.step_limit: int = 10000
        tx_builder.nid: int = 3
        tx_builder.nonce: int = 10000

        return tx_builder

    def _tx_builder_factory(tx_version: str, type_=None) -> TransactionBuilder:
        tx_builder = TransactionBuilder.new(version=tx_version, type_=type_, versioner=TransactionVersioner())

        # Attributes that must be assigned
        tx_builder.signer = Signer.new()

        if tx_version == genesis.version:
            tx_builder = add_attrs_to_genesis_builder(tx_builder)
        elif tx_version == v2.version:
            tx_builder = add_attrs_to_v2_builder(tx_builder)
        elif tx_version == v3.version:
            tx_builder = add_attrs_to_v3_builder(tx_builder)

        return tx_builder

    return _tx_builder_factory


@pytest.fixture
def tx_factory(tx_builder_factory) -> TxFactory:
    def _tx_factory(_tx_builder_factory, tx_version, type_=None) -> Transaction:
        tx_builder: TransactionBuilder = _tx_builder_factory(tx_version=tx_version, type_=type_)
        transaction = tx_builder.build()

        return transaction

    return functools.partial(_tx_factory, tx_builder_factory)
