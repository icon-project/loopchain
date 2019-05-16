from collections import OrderedDict

from loopchain.blockchain.types import Hash32, ExternalAddress, Signature, BloomFilter
from loopchain.blockchain.transactions import TransactionSerializer
from loopchain.blockchain.blocks import Block, BlockSerializer as BaseBlockSerializer
from loopchain.blockchain.blocks.v0_3 import BlockHeader, BlockBody
from loopchain.blockchain.votes.v0_3 import BlockVotes, LeaderVotes


class BlockSerializer(BaseBlockSerializer):
    version = BlockHeader.version
    BlockHeaderClass = BlockHeader
    BlockBodyClass = BlockBody

    def _serialize(self, block: 'Block'):
        header: BlockHeader = block.header
        body: BlockBody = block.body

        transactions = []
        for tx in body.transactions.values():
            ts = TransactionSerializer.new(tx.version, self._tx_versioner)
            tx_serialized = ts.to_full_data(tx)
            transactions.append(tx_serialized)

        return {
            "version": header.version,
            "prevHash": header.prev_hash.hex_0x(),
            "transactionsHash": header.transactions_hash.hex_0x(),
            "stateHash": header.state_hash.hex_0x(),
            "receiptsHash": header.receipts_hash.hex_0x(),
            "repHash": header.rep_hash.hex_0x(),
            "leaderVoteHash": header.leader_vote_hash.hex_0x(),
            "prevVoteHash": header.prev_vote_hash.hex_0x(),
            "bloomFilter": header.bloom_filter.hex_0x(),
            "timestamp": hex(header.timestamp),
            "transactions": transactions,
            "leaderVotes": LeaderVotes.serialize_votes(body.leader_votes),
            "prevVotes": BlockVotes.serialize_votes(body.prev_votes),
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

        rep_hash = json_data["repHash"]
        rep_hash = Hash32.fromhex(rep_hash)

        leader_vote_hash = json_data["leaderVoteHash"]
        leader_vote_hash = Hash32.fromhex(leader_vote_hash)

        prev_vote_hash = json_data["prevVoteHash"]
        prev_vote_hash = Hash32.fromhex(prev_vote_hash)

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
            "rep_hash": rep_hash,
            "leader_vote_hash": leader_vote_hash,
            "prev_vote_hash": prev_vote_hash,
            "bloom_filter": BloomFilter.fromhex(json_data["bloomFilter"])
        }

    def _deserialize_body_data(self, json_data: dict):
        transactions = OrderedDict()
        for tx_data in json_data['transactions']:
            tx_version = self._tx_versioner.get_version(tx_data)
            ts = TransactionSerializer.new(tx_version, self._tx_versioner)
            tx = ts.from_(tx_data)
            transactions[tx.hash] = tx

        leader_votes = LeaderVotes.deserialize_votes(json_data["leaderVotes"])
        prev_votes = BlockVotes.deserialize_votes(json_data["prevVotes"])

        return {
            "transactions": transactions,
            "leader_votes": leader_votes,
            "prev_votes": prev_votes
        }
