from typing import TYPE_CHECKING, List
from loopchain.blockchain.blocks import BlockVerifier as BaseBlockVerifier, BlockBuilder
from loopchain.blockchain.blocks.v0_3 import BlockHeader, BlockBody

if TYPE_CHECKING:
    from loopchain.blockchain.types import ExternalAddress
    from loopchain.blockchain.blocks import Block


class BlockVerifier(BaseBlockVerifier):
    version = BlockHeader.version

    def _verify_common(self, block: 'Block', prev_block: 'Block', generator: 'ExternalAddress'=None, **kwargs):
        header: BlockHeader = block.header
        body: BlockBody = block.body

        # TODO It should check rep's order.
        reps = kwargs.get("reps")
        if header.peer_id not in reps:
            raise RuntimeError(f"Block({header.height}, {header.hash.hex()}, "
                               f"Leader({header.peer_id}) is not in "
                               f"Reps({reps})")
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
                raise RuntimeError(f"Block({header.height}, {header.hash.hex()}, "
                                   f"StateRootHash({header.state_hash}), "
                                   f"Expected({new_block.header.state_hash}).")
            builder.state_hash = new_block.header.state_hash

            builder.receipts = invoke_result
            builder.build_receipt_hash()
            if header.receipt_hash != builder.receipt_hash:
                raise RuntimeError(f"Block({header.height}, {header.hash.hex()}, "
                                   f"ReceiptRootHash({header.receipt_hash.hex()}), "
                                   f"Expected({builder.receipt_hash.hex()}).")

            builder.build_bloom_filter()
            if header.bloom_filter != builder.bloom_filter:
                raise RuntimeError(f"Block({header.height}, {header.hash.hex()}, "
                                   f"ReceiptRootHash({header.bloom_filter.hex()}), "
                                   f"Expected({builder.bloom_filter.hex()}).")

        builder.build_transaction_hash()
        if header.transaction_hash != builder.transaction_hash:
            raise RuntimeError(f"Block({header.height}, {header.hash.hex()}, "
                               f"TransactionRootHash({header.transaction_hash.hex()}), "
                               f"Expected({builder.transaction_hash.hex()}).")

        builder.build_rep_hash()
        if header.rep_hash != builder.rep_hash:
            raise RuntimeError(f"Block({header.height}, {header.hash.hex()}, "
                               f"RepRootHash({header.rep_hash.hex()}), "
                               f"Expected({builder.rep_hash.hex()}).")

        builder.build_prev_vote_hash()
        if header.prev_vote_hash != builder.prev_vote_hash:
            raise RuntimeError(f"Block({header.height}, {header.hash.hex()}, "
                               f"PrevVoteRootHash({header.prev_vote_hash.hex()}), "
                               f"Expected({builder.prev_vote_hash.hex()}).")

        builder.build_hash()
        if header.hash != builder.hash:
            raise RuntimeError(f"Block({header.height}, {header.hash.hex()}, "
                               f"Hash({header.hash.hex()}, "
                               f"Expected({builder.hash.hex()}).")

        if generator:
            self.verify_generator(block, generator)

        return invoke_result

    def verify_generator(self, block: 'Block', generator: 'ExternalAddress'):
        if block.header.peer_id != generator:
            raise RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()}, "
                               f"Generator({block.header.peer_id.hex_xx()}), "
                               f"Expected({generator.hex_xx()}).")

    def verify_prev_block(self, block: 'Block', prev_block: 'Block'):
        super().verify_prev_block(block, prev_block)

        prev_block_header: BlockHeader = prev_block.header
        block_header: BlockHeader = block.header
        block_body: BlockBody = block.body

        next_leader = prev_block_header.next_leader
        if block_body.leader_votes:
            if block_body.leader_votes.old_leader != next_leader:
                raise RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()}, "
                                   f"ComplainedLeader({block_body.leader_votes.old_leader.hex_xx()}), "
                                   f"Expected({prev_block_header.next_leader.hex_xx()}).")
            next_leader = block_body.leader_votes.get_result()

        if next_leader != block_header.peer_id:
            raise RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()}, "
                               f"Leader({block_header.peer_id.hex_xx()}), "
                               f"Expected({next_leader.hex_xx()}).\n "
                               f"LeaderVotes({block_body.leader_votes}")

    def verify_votes(self, block: 'Block', reps: List[str]):
        # reps must be changed to prev_reps, not curr_reps
        body: BlockBody = block.body
        votes = body.prev_votes
        for i, vote in enumerate(votes.votes):
            if vote.rep != reps[i]:
                raise RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()}\n"
                                   f"PreVotes({body.prev_votes})\n"
                                   f"Reps({reps}).")
            if vote.block_height != block.header.height - 1:
                raise RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()}\n"
                                   f"PreVotes({body.prev_votes})")

        leader_votes = body.leader_votes
        if leader_votes:
            for i, vote in enumerate(votes.votes):
                if vote.rep != reps[i]:
                    raise RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()}\n"
                                       f"LeaderVotes({body.leader_votes})\n"
                                       f"Reps({reps}).")
                if vote.block_height != block.header.height - 1:
                    raise RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()}\n"
                                       f"LeaderVotes({body.leader_votes})")

