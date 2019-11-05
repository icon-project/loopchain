import functools
import os
from typing import List

import pytest

from loopchain.blockchain.blocks import Block, BlockBuilder
from loopchain.blockchain.blocks import v0_1a, v0_3
from loopchain.blockchain.transactions import TransactionBuilder, TransactionVersioner
from loopchain.blockchain.transactions import genesis, v2, v3
from loopchain.blockchain.types import ExternalAddress, Address, Hash32, Signature
from loopchain.blockchain.votes.v0_1a import BlockVote, BlockVotes, LeaderVote, LeaderVotes
from loopchain.crypto.signature import Signer


# ----- Global variables
def pytest_configure():
    signers = [Signer.from_prikey(os.urandom(32)) for _ in range(100)]
    reps = [ExternalAddress.fromhex_address(signer.address) for signer in signers]

    pytest.SIGNERS: List[Signer] = signers
    pytest.REPS: List[ExternalAddress] = reps

    pytest.tx_versioner = TransactionVersioner()


# ----- Transactions
@pytest.fixture
def tx_builder_factory():
    def _tx_builder_factory(tx_version: str, type_=None):
        tx_builder = TransactionBuilder.new(version=tx_version, type_=type_, versioner=TransactionVersioner())

        # Attributes that must be assigned
        tx_builder.signer = Signer.new()

        if tx_version == genesis.version:
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
            tx_builder.message = \
                "A rhizome has no beginning or end; " \
                "it is always in the middle, between things, interbeing, intermezzo. " \
                "The tree is filiation, but the rhizome is alliance, uniquely alliance. " \
                "The tree imposes the verb \"to be\" but the fabric of the rhizome is the conjunction, \"and ... and ...and...\"" \
                "This conjunction carries enough force to shake and uproot the verb \"to be.\" " \
                "Where are you going? Where are you coming from? What are you heading for? " \
                "These are totally useless questions.\n\n " \
                "- Mille Plateaux, Gilles Deleuze & Felix Guattari\n\n\"" \
                "Hyperconnect the world\""

        if tx_version == v2.version:
            # Attributes that must be assigned
            tx_builder.to_address = Address(os.urandom(Address.size))
            tx_builder.value: int = 10000
            tx_builder.fee: int = int(0.01 * 10**18)
            tx_builder.nonce: int = 10000

        if tx_version == v3.version:
            # Attributes that must be assigned
            tx_builder.to_address = ExternalAddress(os.urandom(ExternalAddress.size))
            tx_builder.value: int = 10000
            tx_builder.step_limit: int = 10000
            tx_builder.nid: int = 3
            tx_builder.nonce: int = 10000

        return tx_builder

    return _tx_builder_factory


@pytest.fixture
def tx_factory(tx_builder_factory):
    def _tx_factory(_tx_builder_factory, tx_version, type_=None):
        tx_builder: TransactionBuilder = _tx_builder_factory(tx_version=tx_version, type_=type_)
        transaction = tx_builder.build()

        return transaction

    return functools.partial(_tx_factory, _tx_builder_factory=tx_builder_factory)


# ----- Vote & Votes
@pytest.fixture
def block_vote_factory():
    def _vote(signer, block_hash=Hash32(os.urandom(Hash32.size)), timestamp=0, block_height=0, round_=0):
        return BlockVote.new(signer=signer, timestamp=timestamp, block_height=block_height,
                             round_=round_, block_hash=block_hash)
    return _vote


@pytest.fixture
def leader_vote_factory():
    def _vote(signer, old_leader, new_leader, timestamp=0, block_height=0, round_=0):
        return LeaderVote.new(signer=signer, timestamp=timestamp, block_height=block_height, round_=round_,
                              old_leader=old_leader, new_leader=new_leader)
    return _vote


@pytest.fixture
def block_votes_factory():
    def _votes(reps, block_hash, ratio=0.67, block_height=0, round_=0, votes=None):
        return BlockVotes(reps=reps, voting_ratio=ratio, block_height=block_height, round_=round_,
                          block_hash=block_hash, votes=votes)
    return _votes


@pytest.fixture
def leader_votes_factory():
    def _votes(reps, old_leader, voting_ratio=0.51, block_height=0, round_=0, votes=None):
        return LeaderVotes(reps=reps, voting_ratio=voting_ratio, block_height=block_height, round_=round_,
                           old_leader=old_leader, votes=votes)
    return _votes


# ----- Blocks
@pytest.fixture
def block_builder_factory():
    def _wrapped(block_version: str):
        block_builder: BlockBuilder = BlockBuilder.new(version=block_version, tx_versioner=TransactionVersioner())

        # Attributes that must be assigned
        block_builder.height: int = 1
        block_builder.prev_hash: Hash32 = Hash32(os.urandom(Hash32.size))
        block_builder.signer: Signer = Signer.new()

        if block_version == v0_3.version:
            # Attributes that must be assigned
            block_builder.reps = pytest.REPS
            block_builder.next_reps_hash = Hash32(os.urandom(Hash32.size))
            block_builder.leader_votes = []
            block_builder.prev_votes = []
            block_builder.next_leader = pytest.REPS[1]

        # Check - Attributes that must be assigned
        assert block_builder.height
        assert block_builder.prev_hash
        assert block_builder.signer

        # Check - Attributes to be generated
        assert not block_builder.block
        assert not block_builder.hash
        assert not block_builder.signature
        assert not block_builder.peer_id

        return block_builder

    return _wrapped
