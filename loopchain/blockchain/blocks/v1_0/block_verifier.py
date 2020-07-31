from typing import TYPE_CHECKING, Sequence

from lft.consensus.messages.data import DataVerifier

from loopchain import configure_default as conf
from loopchain import utils
from loopchain.blockchain import ExternalAddress
from loopchain.blockchain.blocks import NextRepsChangeReason, v0_5
from loopchain.blockchain.blocks.v1_0 import BlockBuilder
from loopchain.blockchain.exception import BlockVersionNotMatch, TransactionOutOfTimeBound
from loopchain.blockchain.transactions import TransactionVerifier, TransactionVersioner
from loopchain.blockchain.votes import v0_1a
from loopchain.crypto.signature import SignVerifier

if TYPE_CHECKING:
    from loopchain.blockchain.invoke_result import InvokePool
    from loopchain.blockchain.blocks.v1_0.block import Block, BlockHeader


class BlockVerifier(DataVerifier):
    version = "1.0"

    def __init__(self, tx_versioner: TransactionVersioner, invoke_pool: 'InvokePool', reps_getter):
        self._invoke_pool: 'InvokePool' = invoke_pool
        self._tx_versioner: TransactionVersioner = tx_versioner
        self._reps_getter = reps_getter

    async def verify(self, prev_data: 'Block', data: 'Block'):
        self._verify_version(data)
        self._verify_common(prev_data, data)
        self._verify_transactions(data)
        self._verify_signature(data)
        self._invoke_pool.invoke(data, self._tx_versioner)

    def _verify_version(self, block: 'Block'):
        if block.header.version != self.version:
            raise BlockVersionNotMatch(block.header.version, self.version,
                                       f"The block version is incorrect. Block({block.header})")

    def _verify_common(self, prev_block: 'Block', block: 'Block'):
        header: 'BlockHeader' = block.header

        if header.timestamp is None:
            raise RuntimeError(f"Block({header.height}, {header.hash.hex()} does not have timestamp.")
        if header.height > 0 and header.prev_hash is None:
            raise RuntimeError(f"Block({header.height}, {header.hash.hex()} does not have prev_hash.")

        if header.height > 1:
            prev_next_reps_hash = prev_block.header.revealed_next_reps_hash
            if prev_next_reps_hash:
                if prev_next_reps_hash != header.validators_hash:
                    raise RuntimeError(
                        f"Block({header.height}, {header.hash.hex()}, "
                        f"RepsHash({header.validators_hash}), "
                        f"Expected({prev_next_reps_hash}).")
                prev_reps = self._reps_getter(prev_block.header.validators_hash)
            else:
                prev_reps = self._reps_getter(block.header.validators_hash)
            self.verify_prev_votes(block, prev_reps)

    def verify_prev_votes(self, block: 'Block', prev_reps: Sequence['ExternalAddress']):
        prev_votes: 'BlockBody' = block.body.prev_votes

        if prev_votes:
            for vote in prev_votes:
                if vote and vote.version <= '0.5':
                    return self.__verify_prev_votes_by_siever(block, prev_reps, vote)
                self._verify_vote(vote)

    def __verify_prev_votes_by_siever(self, block: 'Block', prev_reps: Sequence['ExternalAddress'], any_vote):
        header: 'BlockHeader' = block.header
        body: 'BlockBody' = block.body
        round_ = 0
        votes_class = None
        if any_vote:
            votes_class = v0_5.BlockVotes if any_vote.version else v0_1a.BlockVotes
            round_ = any_vote.round

        prev_votes = votes_class(
            prev_reps, conf.VOTING_RATIO, header.height - 1, round_, header.prev_hash, body.prev_votes)
        if prev_votes.get_result() is not True:
            raise RuntimeError(f"Block({header.height}, {header.hash.hex()}, PrevVotes {body.prev_votes}")
        try:
            prev_votes.verify()
        except Exception as e:
            # FIXME : votes.verify does not verify all votes when raising an exception.
            raise e
        return True

    def _verify_vote(self, vote: 'BlockVote'):
        invoke_result = self._invoke_pool.get_invoke_data(vote.epoch_num, vote.round_num)

        if invoke_result.state_hash != vote.state_hash:
            raise RuntimeError(
                f"Block({vote.height}, {vote.data_id.hex()}, "
                f"StateRootHash({vote.state_hash.hex()}), "
                f"Expected({invoke_result.state_hash.hex()}).")

        if invoke_result.receipt_hash != vote.receipt_hash:
            raise RuntimeError(
                f"Block({vote.height}, {vote.data_id.hex()}, "
                f"ReceiptRootHash({vote.receipts_hash.hex()}), "
                f"Expected({invoke_result.receipts_hash.hex()}.")

        if invoke_result.next_validators_hash != vote.next_validators_hash:
            raise RuntimeError(
                f"Block({vote.height}, {vote.data_id.hex()}, "
                f"NextValidatorsHash({vote.next_validators_hash.hex()}), "
                f"Expected({invoke_result.next_validators_hash.hex()}.")

        vote.verify()

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

    def _process_next_validators(self, block: 'Block', builder: BlockBuilder, next_validators: dict):
        if next_validators:
            # P-Rep list has been changed
            utils.logger.debug(
                f"_process_next_validators() current_height({block.header.height}),"
                f" next_prep({next_validators})")

            change_reason = NextRepsChangeReason.convert_to_change_reason(next_validators["state"])
            builder.next_validators_change_reason = change_reason
            builder.next_validators = [ExternalAddress.fromhex(prep["id"]) for prep in next_validators['nextReps']]
