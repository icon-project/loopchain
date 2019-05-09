from typing import TYPE_CHECKING, List
from loopchain.blockchain.blocks import BlockVerifier as BaseBlockVerifier, BlockBuilder
from loopchain.blockchain.blocks.v0_3 import BlockHeader, BlockBody
from loopchain.blockchain.types import ExternalAddress, Signature

if TYPE_CHECKING:
    from loopchain.blockchain.blocks import Block


class BlockVerifier(BaseBlockVerifier):
    version = BlockHeader.version

    def _verify_common(self, block: 'Block', prev_block: 'Block', generator: 'ExternalAddress'=None, **kwargs):
        header: BlockHeader = block.header
        body: BlockBody = block.body

        # TODO It should check rep's order.
        reps = kwargs.get("reps")
        if header.height > 0 and header.peer_id not in reps:
            exception = RuntimeError(f"Block({header.height}, {header.hash.hex()}, "
                                     f"Leader({header.peer_id}) is not in "
                                     f"Reps({reps})")
            self._handle_exception(exception)
        if header.peer_id not in reps:
            exception = RuntimeError(f"Block({header.height}, {header.hash.hex()}, "
                                     f"Leader({header.peer_id}) is not in "
                                     f"Reps({reps})")
            self._handle_exception(exception)
        if header.height > 1:
            self.verify_votes(block, reps)

        builder = BlockBuilder.from_new(block, self._tx_versioner)
        builder.reset_cache()
        builder.peer_id = block.header.peer_id
        builder.signature = block.header.signature
        builder.reps = reps

        for tx in body.transactions.values():
            builder.transactions[tx.hash] = tx

        invoke_result = None
        if self.invoke_func:
            new_block, invoke_result = self.invoke_func(block)
            if header.state_hash != new_block.header.state_hash:
                exception = RuntimeError(f"Block({header.height}, {header.hash.hex()}, "
                                         f"StateRootHash({header.state_hash}), "
                                         f"Expected({new_block.header.state_hash}).")
                self._handle_exception(exception)
            builder.state_hash = new_block.header.state_hash

            builder.receipts = invoke_result
            builder.build_receipt_hash()
            if header.receipt_hash != builder.receipt_hash:
                exception = RuntimeError(f"Block({header.height}, {header.hash.hex()}, "
                                         f"ReceiptRootHash({header.receipt_hash.hex()}), "
                                         f"Expected({builder.receipt_hash.hex()}).")
                self._handle_exception(exception)

            builder.build_bloom_filter()
            if header.bloom_filter != builder.bloom_filter:
                exception = RuntimeError(f"Block({header.height}, {header.hash.hex()}, "
                                         f"ReceiptRootHash({header.bloom_filter.hex()}), "
                                         f"Expected({builder.bloom_filter.hex()}).")
                self._handle_exception(exception)

        builder.build_transaction_hash()
        if header.transaction_hash != builder.transaction_hash:
            exception = RuntimeError(f"Block({header.height}, {header.hash.hex()}, "
                                     f"TransactionRootHash({header.transaction_hash.hex()}), "
                                     f"Expected({builder.transaction_hash.hex()}).")
            self._handle_exception(exception)

        builder.build_rep_hash()
        if header.rep_hash != builder.rep_hash:
            exception = RuntimeError(f"Block({header.height}, {header.hash.hex()}, "
                                     f"RepRootHash({header.rep_hash.hex()}), "
                                     f"Expected({builder.rep_hash.hex()}).")
            self._handle_exception(exception)

        builder.build_prev_vote_hash()
        if header.prev_vote_hash != builder.prev_vote_hash:
            exception = RuntimeError(f"Block({header.height}, {header.hash.hex()}, "
                                     f"PrevVoteRootHash({header.prev_vote_hash.hex()}), "
                                     f"Expected({builder.prev_vote_hash.hex()}).")
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

    def verify_prev_block(self, block: 'Block', prev_block: 'Block'):
        super().verify_prev_block(block, prev_block)

        prev_block_header: BlockHeader = prev_block.header
        block_header: BlockHeader = block.header
        block_body: BlockBody = block.body

        if block_header.height > 1:
            if block_body.prev_votes.block_height != prev_block.header.height:
                exception = RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()}, "
                                         f"PrevVoteBlockHeight({block_body.prev_votes.block_height}), "
                                         f"Expected({prev_block.header.height}).")
                self._handle_exception(exception)

            if block_body.prev_votes.block_hash != prev_block.header.hash:
                exception = RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()}, "
                                         f"PrevVoteBlockHash({block_body.prev_votes.block_hash}), "
                                         f"Expected({prev_block.header.hash}).")
                self._handle_exception(exception)

            if block_body.prev_votes.get_result() is not True:
                exception = RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()}, "
                                         f"PrevVotes {block_body.prev_votes}")
                self._handle_exception(exception)

        if block_body.leader_votes.old_leader != ExternalAddress.empty():
            if block_body.leader_votes.get_result() != block.header.peer_id:
                exception = RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()}, "
                                         f"Leader({block.header.peer_id.hex_xx()}), "
                                         f"Expected({block_body.leader_votes.get_result()}).")
                self._handle_exception(exception)
        else:
            if prev_block_header.next_leader != block_header.peer_id:
                exception = RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()}, "
                                         f"Leader({block_header.peer_id.hex_xx()}), "
                                         f"Expected({prev_block_header.next_leader.hex_xx()}).\n "
                                         f"LeaderVotes({block_body.leader_votes}")
                self._handle_exception(exception)

    def verify_votes(self, block: 'Block', reps: List[str]):
        # reps must be changed to prev_reps, not curr_reps
        body: BlockBody = block.body
        votes = body.prev_votes

        if list(votes.reps) != reps:
            exception = RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()}\n"
                                     f"PreVotesReps({body.prev_votes.reps}), "
                                     f"Expected({reps})")
            self._handle_exception(exception)

        if votes.block_height != block.header.height - 1:
            exception = RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()}\n"
                                     f"PreVotesBlockHeight({body.prev_votes.block_height}), "
                                     f"Expected({block.header.height - 1})")
            self._handle_exception(exception)
        if votes.block_hash != block.header.prev_hash:
            exception = RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()}\n"
                                     f"PreVotesBlockHash({body.prev_votes.block_hash}), "
                                     f"Expected({block.header.prev_hash})")
            self._handle_exception(exception)

        try:
            votes.verify()
        except Exception as e:
            # FIXME : votes.verify does not verify all votes when raising an exception.
            self._handle_exception(e)

        leader_votes = body.leader_votes
        if leader_votes.old_leader != ExternalAddress.empty():
            if list(leader_votes.reps) != reps:
                exception = RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()}\n"
                                         f"LeaderVotesReps({leader_votes.reps}), "
                                         f"Expected({reps})")
                self._handle_exception(exception)
            if leader_votes.block_height != block.header.height:
                exception = RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()}\n"
                                         f"LeaderVotesBlockHeight({leader_votes.block_height}), "
                                         f"Expected({block.header.height})")
                self._handle_exception(exception)
            try:
                leader_votes.verify()
            except Exception as e:
                # FIXME : leader_votes.verify does not verify all votes when raising an exception.
                self._handle_exception(e)
