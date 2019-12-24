# Copyright 2018-current ICON Foundation
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
"""block verifier for version 0.5 block"""

from typing import TYPE_CHECKING, Sequence

from loopchain import configure as conf
from loopchain.blockchain.blocks.v0_4 import BlockVerifier
from loopchain.blockchain.blocks.v0_5 import BlockHeader, BlockBody
from loopchain.blockchain.types import ExternalAddress
from loopchain.blockchain.votes import v0_1a, v0_5

if TYPE_CHECKING:
    from loopchain.blockchain.blocks import Block


class BlockVerifier(BlockVerifier):
    version = BlockHeader.version

    def verify_leader_votes(self, block: 'Block', prev_block: 'Block', reps: Sequence[ExternalAddress]):
        body: BlockBody = block.body
        if body.leader_votes:
            any_vote = next(vote for vote in body.leader_votes if vote)
            votes_class = v0_5.LeaderVotes if any_vote.version else v0_1a.LeaderVotes
            leader_votes = votes_class(
                reps, conf.VOTING_RATIO,
                block.header.height, any_vote.round, any_vote.old_leader, body.leader_votes)
            if leader_votes.get_result() == ExternalAddress.empty():
                if leader_votes.block_height != block.header.height:
                    exception = RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()}, "
                                             f"Height({block.header.height}), "
                                             f"Expected({leader_votes.round}).")
                    self._handle_exception(exception)
            elif leader_votes.get_result() != block.header.peer_id:
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
        votes_class = None
        if body.prev_votes:
            any_vote = next(vote for vote in body.prev_votes if vote)
            votes_class = v0_5.BlockVotes if any_vote.version else v0_1a.BlockVotes
            round_ = any_vote.round

        prev_votes = votes_class(
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


