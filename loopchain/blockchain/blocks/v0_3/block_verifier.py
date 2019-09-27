# Copyright 2019 ICON Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""block verifier for version 0.3 block"""

from typing import TYPE_CHECKING, Callable, Sequence

from loopchain import configure as conf
from loopchain.blockchain.blocks import BlockVerifier as BaseBlockVerifier, BlockBuilder
from loopchain.blockchain.blocks.v0_3 import BlockHeader, BlockBody
from loopchain.blockchain.exception import NotInReps
from loopchain.blockchain.types import ExternalAddress, Hash32
from loopchain.blockchain.votes.v0_3 import BlockVotes, LeaderVotes

if TYPE_CHECKING:
    from loopchain.blockchain.blocks import Block


class BlockVerifier(BaseBlockVerifier):
    version = BlockHeader.version

    # noinspection PyMethodOverriding
    def _verify_common(self, block: 'Block', prev_block: 'Block', generator: 'ExternalAddress'=None, *,
                       reps_getter: Callable[[Sequence[ExternalAddress]], Hash32]):
        header: BlockHeader = block.header
        body: BlockBody = block.body

        # TODO It should check rep's order.
        reps = reps_getter(header.reps_hash)
        if header.peer_id not in reps:
            exception = NotInReps(f"Block({header.height}, {header.hash.hex()}, "
                                  f"Leader({header.peer_id}) is not in Reps({reps})")
            self._handle_exception(exception)

        if header.height > 0:
            self.verify_leader_votes(block, prev_block, reps)

        if header.height > 1:
            prev_next_reps_hash = prev_block.header.revealed_next_reps_hash
            if prev_next_reps_hash:
                if prev_next_reps_hash != header.reps_hash:
                    exception = RuntimeError(f"Block({header.height}, {header.hash.hex()}, "
                                             f"RepsHash({header.reps_hash}), "
                                             f"Expected({prev_next_reps_hash}).")
                    self._handle_exception(exception)
                prev_reps = reps_getter(prev_block.header.reps_hash)
            else:
                prev_reps = reps
            self.verify_prev_votes(block, prev_reps)

        builder = BlockBuilder.from_new(block, self._tx_versioner)
        builder.reset_cache()
        builder.peer_id = block.header.peer_id
        builder.signature = block.header.signature
        builder.reps = reps

        for tx in body.transactions.values():
            builder.transactions[tx.hash] = tx

        invoke_result = None
        if self.invoke_func:
            self.verify_invoke(builder, block, prev_block)

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
                                     f"Expected({builder.hash.hex()}), "
                                     f"header({header}), "
                                     f"builder({builder.build_block_header_data()}).")
            self._handle_exception(exception)

        if generator:
            self.verify_generator(block, generator)

        return invoke_result

    def verify_invoke(self, builder: 'BlockBuilder', block: 'Block', prev_block: 'Block'):
        new_block, invoke_result = self.invoke_func(block, prev_block)
        header: BlockHeader = block.header
        new_header: BlockHeader = new_block.header
        if header.state_hash != new_header.state_hash:
            exception = RuntimeError(f"Block({header.height}, {header.hash.hex()}, "
                                     f"StateRootHash({header.state_hash}), "
                                     f"Expected({new_header.state_hash}).")
            self._handle_exception(exception)

        if header.next_reps_hash != new_header.next_reps_hash:
            if (not new_header.prep_changed
                    and header.next_reps_hash == new_header.revealed_next_reps_hash):
                pass
            else:
                exception = RuntimeError(f"Block({header.height}, {header.hash.hex()}, "
                                         f"NextRepsHash({header.next_reps_hash}), "
                                         f"Expected({new_header.next_reps_hash}), "
                                         f"revealed_next_reps_hash({new_header.revealed_next_reps_hash}), "
                                         f"\norigin header({header}), "
                                         f"\nnew block header({new_header}).")
                self._handle_exception(exception)

        builder.state_hash = new_header.state_hash
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

    def verify_generator(self, block: 'Block', generator: 'ExternalAddress'):
        if not block.header.complained and block.header.peer_id != generator:
            exception = RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()}, "
                                     f"Generator({block.header.peer_id.hex_xx()}), "
                                     f"Expected({generator.hex_xx()}).")
            self._handle_exception(exception)

    def verify_leader_votes(self, block: 'Block', prev_block: 'Block',  reps: Sequence[ExternalAddress]):
        body: BlockBody = block.body
        if body.leader_votes:
            any_vote = next(vote for vote in body.leader_votes if vote)
            leader_votes = LeaderVotes(
                reps, conf.LEADER_COMPLAIN_RATIO,
                block.header.height, any_vote.round_, any_vote.old_leader, body.leader_votes)
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
            if prev_block_header.next_leader != block.header.peer_id and not prev_block_header.prep_changed:
                exception = RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()}, "
                                         f"Leader({block.header.peer_id.hex_xx()}), "
                                         f"Expected({prev_block_header.next_leader.hex_xx()}).\n "
                                         f"LeaderVotes({body.leader_votes}")
                self._handle_exception(exception)

    def verify_prev_votes(self, block: 'Block', prev_reps: Sequence[ExternalAddress]):
        header: BlockHeader = block.header
        body: BlockBody = block.body
        round_ = 0
        if body.prev_votes:
            round_ = next(vote for vote in body.prev_votes if vote).round_

        prev_votes = BlockVotes(
            prev_reps, conf.VOTING_RATIO, header.height - 1, round_, header.prev_hash, body.prev_votes)
        if prev_votes.get_result() is not True:
            exception = RuntimeError(f"Block({header.height}, {header.hash.hex()}, "
                                     f"PrevVotes {body.prev_votes}")
            self._handle_exception(exception)
        try:
            prev_votes.verify()
        except Exception as e:
            # FIXME : votes.verify does not verify all votes when raising an exception.
            self._handle_exception(e)


