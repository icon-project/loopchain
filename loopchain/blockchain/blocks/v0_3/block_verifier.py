from typing import TYPE_CHECKING, List
from loopchain import configure as conf
from loopchain.blockchain.blocks import BlockVerifier as BaseBlockVerifier, BlockBuilder
from loopchain.blockchain.blocks.v0_3 import BlockHeader, BlockBody
from loopchain.blockchain.votes.v0_3 import BlockVotes, LeaderVotes
from loopchain.blockchain.types import ExternalAddress

if TYPE_CHECKING:
    from loopchain.blockchain.blocks import Block


class BlockVerifier(BaseBlockVerifier):
    version = BlockHeader.version

    def _verify_common(self, block: 'Block', prev_block: 'Block', generator: 'ExternalAddress'=None, **kwargs):
        header: BlockHeader = block.header
        body: BlockBody = block.body

        # TODO It should check rep's order.
        reps = kwargs.get("reps")
        if header.peer_id not in reps:
            exception = RuntimeError(f"Block({header.height}, {header.hash.hex()}, "
                                     f"Leader({header.peer_id}) is not in "
                                     f"Reps({reps})")
            self._handle_exception(exception)

        if header.height > 0:
            self.verify_leader_votes(block, prev_block, reps)
        if header.height > 1:
            self.verify_prev_votes(block, reps)

        builder = BlockBuilder.from_new(block, self._tx_versioner)
        builder.reset_cache()
        builder.peer_id = block.header.peer_id
        builder.signature = block.header.signature
        builder.reps = reps

        for tx in body.transactions.values():
            builder.transactions[tx.hash] = tx

        invoke_result = None
        if self.invoke_func:
            new_block, invoke_result = self.invoke_func(block, prev_block)
            if header.state_hash != new_block.header.state_hash:
                exception = RuntimeError(f"Block({header.height}, {header.hash.hex()}, "
                                         f"StateRootHash({header.state_hash}), "
                                         f"Expected({new_block.header.state_hash}).")
                self._handle_exception(exception)
            builder.state_hash = new_block.header.state_hash

            builder.receipts = invoke_result
            builder.build_receipts_hash()
            if header.receipts_hash != builder.receipts_hash:
                exception = RuntimeError(f"Block({header.height}, {header.hash.hex()}, "
                                         f"ReceiptRootHash({header.receipts_hash.hex()}), "
                                         f"Expected({builder.receipts_hash.hex()}).")
                self._handle_exception(exception)

            builder.build_logs_bloom()
            if header.logs_bloom != builder.logs_bloom:
                exception = RuntimeError(f"Block({header.height}, {header.hash.hex()}, "
                                         f"LogsBloom({header.logs_bloom.hex()}), "
                                         f"Expected({builder.logs_bloom.hex()}).")
                self._handle_exception(exception)

        builder.build_transactions_hash()
        if header.transactions_hash != builder.transactions_hash:
            exception = RuntimeError(f"Block({header.height}, {header.hash.hex()}, "
                                     f"TransactionsRootHash({header.transactions_hash.hex()}), "
                                     f"Expected({builder.transactions_hash.hex()}).")
            self._handle_exception(exception)

        builder.build_reps_hash()
        if header.reps_hash != builder.reps_hash:
            exception = RuntimeError(f"Block({header.height}, {header.hash.hex()}, "
                                     f"RepRootHash({header.reps_hash.hex()}), "
                                     f"Expected({builder.reps_hash.hex()}).")
            self._handle_exception(exception)

        builder.build_prev_votes_hash()
        if header.prev_votes_hash != builder.prev_votes_hash:
            exception = RuntimeError(f"Block({header.height}, {header.hash.hex()}, "
                                     f"PrevVoteRootHash({header.prev_votes_hash.hex()}), "
                                     f"Expected({builder.prev_votes_hash.hex()}).")
            self._handle_exception(exception)

        builder.build_hash()
        if header.hash != builder.hash:
            exception = RuntimeError(f"Block({header.height}, {header.hash.hex()}, "
                                     f"Hash({header.hash.hex()}, "
                                     f"Expected({builder.hash.hex()}).")
            self._handle_exception(exception)

        if generator:
            self.verify_generator(block, generator)

        return invoke_result

    def verify_generator(self, block: 'Block', generator: 'ExternalAddress'):
        if not block.header.complained and block.header.peer_id != generator:
            exception = RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()}, "
                                     f"Generator({block.header.peer_id.hex_xx()}), "
                                     f"Expected({generator.hex_xx()}).")
            self._handle_exception(exception)

    def verify_leader_votes(self, block: 'Block', prev_block: 'Block',  reps: List[ExternalAddress]):
        body: BlockBody = block.body
        if body.leader_votes:
            any_vote = next(vote for vote in body.leader_votes if vote)
            leader_votes = LeaderVotes(reps, conf.LEADER_COMPLAIN_RATIO,
                                       block.header.height, any_vote.old_leader, body.leader_votes)
            if leader_votes.get_result() != block.header.peer_id:
                exception = RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()}, "
                                         f"Leader({block.header.peer_id.hex_xx()}), "
                                         f"Expected({leader_votes.get_result()}).")
                self._handle_exception(exception)
            try:
                leader_votes.verify()
            except Exception as e:
                # FIXME : leader_votes.verify does not verify all votes when raising an exception.
                self._handle_exception(e)
        else:
            prev_block_header: BlockHeader = prev_block.header
            if prev_block_header.next_leader != block.header.peer_id:
                exception = RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()}, "
                                         f"Leader({block.header.peer_id.hex_xx()}), "
                                         f"Expected({prev_block_header.next_leader.hex_xx()}).\n "
                                         f"LeaderVotes({body.leader_votes}")
                self._handle_exception(exception)

    def verify_prev_votes(self, block: 'Block', reps: List[ExternalAddress]):
        header: BlockHeader = block.header
        body: BlockBody = block.body

        prev_votes = BlockVotes(reps, conf.VOTING_RATIO, header.height - 1, header.prev_hash, body.prev_votes)
        if prev_votes.get_result() is not True:
            exception = RuntimeError(f"Block({header.height}, {header.hash.hex()}, "
                                     f"PrevVotes {body.prev_votes}")
            self._handle_exception(exception)
        try:
            prev_votes.verify()
        except Exception as e:
            # FIXME : votes.verify does not verify all votes when raising an exception.
            self._handle_exception(e)
