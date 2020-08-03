from typing import TYPE_CHECKING, Sequence

from lft.consensus.messages.data import DataVerifier
from pkg_resources import parse_version

from loopchain import configure_default as conf
from loopchain import utils
from loopchain.blockchain import Votes
from loopchain.blockchain.exception import BlockVersionNotMatch, TransactionOutOfTimeBound
from loopchain.blockchain.transactions import TransactionVerifier, TransactionVersioner
from loopchain.crypto.signature import SignVerifier

if TYPE_CHECKING:
    from loopchain.blockchain.types import ExternalAddress
    from loopchain.blockchain.invoke_result import InvokePool
    from loopchain.blockchain.blocks.v1_0.block import Block, BlockHeader


class BlockVerifier(DataVerifier):
    version = "1.0"

    def __init__(self, tx_versioner: TransactionVersioner, invoke_pool: 'InvokePool', reps_getter):
        self._invoke_pool: 'InvokePool' = invoke_pool
        self._tx_versioner: TransactionVersioner = tx_versioner
        self._reps_getter = reps_getter

    async def verify(self, prev_block: 'Block', block: 'Block'):
        self._verify_version(block)
        self._verify_common(block)

        if block.header.height > 1:
            self._verify_prev_votes(prev_block, block)

        self._verify_transactions(block)
        self._verify_signature(block)
        self._invoke_pool.invoke(block, self._tx_versioner)

    def _verify_version(self, block: 'Block'):
        if block.header.version != self.version:
            raise BlockVersionNotMatch(block.header.version, self.version,
                                       f"The block version is incorrect. Block({block.header})")

    def _verify_common(self, block: 'Block'):
        header: 'BlockHeader' = block.header

        if header.timestamp is None:
            raise RuntimeError(f"Block({header.height}, {header.hash.hex()} does not have timestamp.")
        if header.height > 0 and header.prev_hash is None:
            raise RuntimeError(f"Block({header.height}, {header.hash.hex()} does not have prev_hash.")

    def _verify_prev_votes(self, prev_block: 'Block', block: 'Block'):
        prev_votes: 'BlockBody' = block.body.prev_votes
        for vote in prev_votes:
            # Check for only a vote made by `Siever`.
            if not vote:
                continue

            if parse_version(vote.version) <= parse_version('0.5'):
                header: 'BlockHeader' = block.header
                prev_next_reps_hash = prev_block.header.revealed_next_reps_hash
                if prev_next_reps_hash:
                    if prev_next_reps_hash != header.validators_hash:
                        raise RuntimeError(
                            f"Block({header.height}, {header.hash.hex()}, "
                            f"RepsHash({header.reps_hash}), "
                            f"Expected({prev_next_reps_hash}).")
                    prev_reps = self._reps_getter(prev_block.header.reps_hash)
                else:
                    prev_reps = self._reps_getter(header.reps_hash)

                return self._verify_prev_votes_by_siever(block, prev_reps, vote)

            vote.verify()

    def _verify_prev_votes_by_siever(self, block: 'Block', prev_reps: Sequence['ExternalAddress'], any_vote):
        header: 'BlockHeader' = block.header
        body: 'BlockBody' = block.body
        votes_class = Votes.get_block_votes_class(any_vote.version)
        round_ = any_vote.round
        prev_votes = votes_class(
            prev_reps, conf.VOTING_RATIO, header.height - 1, round_, header.prev_hash, body.prev_votes
        )

        if prev_votes.get_result() is not True:
            raise RuntimeError(f"Block({header.height}, {header.hash.hex()}), PrevVotes {body.prev_votes}")

        try:
            prev_votes.verify()
        except Exception as e:
            raise e

        return True

    def _verify_transactions(self, block: 'Block'):
        for tx in block.body.transactions.values():
            if not utils.is_in_time_boundary(tx.timestamp, conf.TIMESTAMP_BOUNDARY_SECOND, block.header.timestamp):
                raise TransactionOutOfTimeBound(tx, block.header.timestamp)

            tv = TransactionVerifier.new(tx.version, tx.type(), self._tx_versioner)
            tv.verify(tx)

    def _verify_signature(self, block: 'Block'):
        sign_verifier = SignVerifier.from_address(block.header.peer_id.hex_xx())
        try:
            sign_verifier.verify_hash(block.header.hash, block.header.signature)
        except Exception as e:
            raise RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()}, Invalid Signature {e}")
