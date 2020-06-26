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


@pytest.fixture
def icon_preinvoke() -> dict:
    """Suppose that I request PreInvoke to ICON-Service.

    Note that no value will be returned before Rev. 6.
    """

    return {
        "addedTransactions": {
            "6804dd2ccd9a9d17136d687838aa09e02334cd4afa964d75993f18991ee874de": {
                "version": "0x3",
                "timestamp": "0x563a6cf330136",
                "dataType": "base",
                "data": {
                    "prep": {
                        "incentive": "0x1",
                        "rewardRate": "0x1",
                        "totalDelegation": "0x3872423746291",
                        "value": "0x7800000"
                    }
                }
            }
        },
        "currentRepsHash": "1d04dd2ccd9a9d14416d6878a8aa09e02334cd4afa964d75993f2e991ee874de",
    }


@pytest.fixture
def icon_invoke() -> dict:
    """Get invoke result from ICON-Service.

    TODO: Check that the all data have valid key and value, especially hash prefix!
    """

    return {
        "txResults": [
            {
                "status": "0x1",
                "txHash": "c71303ef8543d04b5dc1ba6579132b143087c68db1b2168786408fcbce568238",
                "txIndex": "0x0",
                "blockHeight": "0x1234",
                "blockHash": "c71303ef8543d04b5dc1ba6579132b143087c68db1b2168786408fcbce568238",
                "cumulativeStepUsed": "0x1234",
                "stepUsed": "0x1234",
                "stepPrice": "0x100",
                "scoreAddress": "cxb0776ee37f5b45bfaea8cff1d8232fbb6122ec32"
            }
        ],
        "stateRootHash": "c71303ef8543d04b5dc1ba6579132b143087c68db1b2168786408fcbce568238",
        "addedTransactions": {
            "6804dd2ccd9a9d17136d687838aa09e02334cd4afa964d75993f18991ee874de": {
                "version": "0x3",
                "timestamp": "0x563a6cf330136",
                "dataType": "base",
                "data": {
                    "prep": {
                        "incentive": "0x1",
                        "rewardRate": "0x1",
                        "totalDelegation": "0x3872423746291",
                        "value": "0x7800000"
                    }
                }
            }
        },
        "prep": {
            "nextReps": [
                {
                    "id": "hx86aba2210918a9b116973f3c4b27c41a54d5dafe",
                    "p2pEndpoint": "123.45.67.89:7100"
                },
                {
                    "id": "hx13aca3210918a9b116973f3c4b27c41a54d5dad1",
                    "p2pEndPoint": "210.34.56.17:7100"
                }
            ],
            "irep": "0x1",
            "state": "0x0",
            "rootHash": "c7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        }
    }
