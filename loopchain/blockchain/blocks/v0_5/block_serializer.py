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

from loopchain.blockchain.blocks import Block, BlockSerializer as BaseBlockSerializer
from loopchain.blockchain.blocks.v0_5 import BlockHeader, BlockBody
from loopchain.blockchain.transactions import TransactionSerializer
from loopchain.blockchain.types import Hash32, ExternalAddress, Signature, BloomFilter
from loopchain.blockchain.votes import v0_1a
from loopchain.blockchain.votes.v0_5 import BlockVotes, LeaderVotes


class BlockSerializer(BaseBlockSerializer):
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

    def _deserialize_header_data(self, json_data: dict):
        hash_ = Hash32.fromhex(json_data["hash"])

        prev_hash = json_data.get('prevHash')
        prev_hash = Hash32.fromhex(prev_hash) if prev_hash else None

        peer_id = json_data.get('leader')
        peer_id = ExternalAddress.fromhex(peer_id) if peer_id else None

        signature = json_data.get('signature')
        signature = Signature.from_base64str(signature) if signature else None

        next_leader = json_data.get("nextLeader")
        next_leader = ExternalAddress.fromhex(next_leader) if next_leader else None

        transactions_hash = json_data["transactionsHash"]
        transactions_hash = Hash32.fromhex(transactions_hash)

        receipts_hash = json_data["receiptsHash"]
        receipts_hash = Hash32.fromhex(receipts_hash)

        state_hash = json_data["stateHash"]
        state_hash = Hash32.fromhex(state_hash)

        reps_hash = json_data["repsHash"]
        reps_hash = Hash32.fromhex(reps_hash)

        next_reps_hash = json_data["nextRepsHash"]
        next_reps_hash = Hash32.fromhex(next_reps_hash)

        leader_votes_hash = json_data["leaderVotesHash"]
        leader_votes_hash = Hash32.fromhex(leader_votes_hash)

        prev_votes_hash = json_data["prevVotesHash"]
        prev_votes_hash = Hash32.fromhex(prev_votes_hash)

        height = json_data["height"]
        height = int(height, 16)

        timestamp = json_data["timestamp"]
        timestamp = int(timestamp, 16)

        return {
            "hash": hash_,
            "prev_hash": prev_hash,
            "height": height,
            "timestamp": timestamp,
            "peer_id": peer_id,
            "signature": signature,
            "next_leader": next_leader,
            "transactions_hash": transactions_hash,
            "receipts_hash": receipts_hash,
            "state_hash": state_hash,
            "reps_hash": reps_hash,
            "next_reps_hash": next_reps_hash,
            "leader_votes_hash": leader_votes_hash,
            "prev_votes_hash": prev_votes_hash,
            "logs_bloom": BloomFilter.fromhex(json_data["logsBloom"])
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
