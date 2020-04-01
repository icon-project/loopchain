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
"""block serializer for version 0.5 block"""

from collections import OrderedDict

from legacy.blockchain.blocks.v0_4 import BlockSerializer
from legacy.blockchain.blocks.v0_5 import BlockHeader, BlockBody
from legacy.blockchain.transactions import TransactionSerializer
from legacy.blockchain.votes import v0_1a
from legacy.blockchain.votes.v0_5 import BlockVotes, LeaderVotes


class BlockSerializer(BlockSerializer):
    version = BlockHeader.version
    BlockHeaderClass = BlockHeader
    BlockBodyClass = BlockBody

    def _serialize(self, block: 'Block'):
        header: BlockHeader = block.header
        body: BlockBody = block.body

        transactions = []
        for tx in body.transactions.values():
            ts = TransactionSerializer.new(tx.version, tx.type(), self._tx_versioner)
            tx_serialized = ts.to_full_data(tx)
            transactions.append(tx_serialized)

        vote_class = BlockVotes
        leader_vote_class = LeaderVotes
        if body.prev_votes:
            any_vote = next(vote for vote in body.prev_votes if vote)
            if any_vote.version is None:
                vote_class = v0_1a.BlockVotes
                leader_vote_class = v0_1a.LeaderVotes

        return {
            "version": header.version,
            "prevHash": header.prev_hash.hex_0x(),
            "transactionsHash": header.transactions_hash.hex_0x(),
            "stateHash": header.state_hash.hex_0x(),
            "receiptsHash": header.receipts_hash.hex_0x(),
            "repsHash": header.reps_hash.hex_0x(),
            "nextRepsHash": header.next_reps_hash.hex_0x(),
            "leaderVotesHash": header.leader_votes_hash.hex_0x(),
            "prevVotesHash": header.prev_votes_hash.hex_0x(),
            "logsBloom": header.logs_bloom.hex_0x(),
            "timestamp": hex(header.timestamp),
            "transactions": transactions,
            "leaderVotes": leader_vote_class.serialize_votes(body.leader_votes),
            "prevVotes": vote_class.serialize_votes(body.prev_votes),
            "hash": header.hash.hex_0x(),
            "height": hex(header.height),
            "leader": header.peer_id.hex_hx(),
            "signature": header.signature.to_base64str(),
            "nextLeader": header.next_leader.hex_xx(),
        }

    def _deserialize_body_data(self, json_data: dict):
        transactions = OrderedDict()
        for tx_data in json_data['transactions']:
            tx_version, tx_type = self._tx_versioner.get_version(tx_data)
            ts = TransactionSerializer.new(tx_version, tx_type, self._tx_versioner)
            tx = ts.from_(tx_data)
            transactions[tx.hash] = tx

        vote_class = BlockVotes
        leader_vote_class = LeaderVotes
        if json_data["prevVotes"]:
            any_vote = next(vote for vote in json_data["prevVotes"] if vote)
            if any_vote.get("round") is None:
                vote_class = v0_1a.BlockVotes
                leader_vote_class = v0_1a.LeaderVotes

        leader_votes = leader_vote_class.deserialize_votes(json_data["leaderVotes"])
        prev_votes = vote_class.deserialize_votes(json_data["prevVotes"])

        return {
            "transactions": transactions,
            "leader_votes": leader_votes,
            "prev_votes": prev_votes
        }
