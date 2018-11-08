from collections import OrderedDict
from . import BlockHeader, BlockBody
from .. import Block, BlockSerializer as BaseBlockSerializer
from ... import Address, Signature, Hash32, BlockVersionNotMatch, TransactionSerializer, TransactionVersions


class BlockSerializer(BaseBlockSerializer):
    def serialize(self, block: 'Block'):
        if block.header.version != BlockHeader.version:
            raise BlockVersionNotMatch(block.header.version, BlockHeader.version,
                                       "The block of this version cannot be serialized by the serializer.")
        header: BlockHeader = block.header
        body: BlockBody = block.body

        tv = TransactionVersions()
        transactions = list()
        for tx in body.transactions.values():
            tx_hash_generator_version = tv.get_hash_generator_version(tx.version)
            ts = TransactionSerializer.new(tx.version, tx_hash_generator_version)
            tx_serialized = ts.serialize(tx)
            transactions.append(tx_serialized)

        return {
            "version": header.version,
            "prev_block_hash": header.prev_hash.hex() if header.prev_hash else '',
            "merkle_tree_root_hash": header.merkle_tree_root_hash.hex(),
            "time_stamp": header.timestamp,
            "confirmed_transaction_list": transactions,
            "block_hash": header.hash.hex(),
            "height": header.height,
            "peer_id": header.peer_id.hex() if header.peer_id else '',
            "signature": header.signature.to_base64str() if header.signature else '',
            "commit_state": header.commit_state
        }

    def deserialize(self, json_data):
        if json_data['version'] != BlockHeader.version:
            raise BlockVersionNotMatch(json_data['version'], BlockHeader.version,
                                       "The block of this version cannot be deserialized by the serializer.")

        prev_hash = json_data.get('prev_block_hash')
        prev_hash = Hash32.fromhex(prev_hash) if prev_hash else None

        peer_id = json_data.get('peer_id')
        peer_id = Address.fromhex(peer_id) if peer_id else None

        signature = json_data.get('signature')
        signature = Signature.from_base64str(signature) if signature else None

        next_leader = json_data.get("next_leader")
        next_leader = Address.fromhex(next_leader) if next_leader else None

        votes = json_data.get("votes")

        header = BlockHeader(
            hash=Hash32.fromhex(json_data["block_hash"]),
            prev_hash=prev_hash,
            height=json_data["height"],
            timestamp=json_data["time_stamp"],
            peer_id=peer_id,
            signature=signature,
            next_leader=next_leader,
            merkle_tree_root_hash=Hash32.fromhex(json_data["merkle_tree_root_hash"]),
            commit_state=json_data.get("commit_state")
        )

        tv = TransactionVersions()
        transactions = OrderedDict()
        for tx_data in json_data['confirmed_transaction_list']:
            tx_version = tv.get_version(tx_data)
            tx_hash_generator_version = tv.get_hash_generator_version(tx_version)
            ts = TransactionSerializer.new(tx_version, tx_hash_generator_version)
            tx = ts.deserialize(tx_data)
            transactions[tx.hash] = tx

        body = BlockBody(transactions, votes)
        return Block(header, body)
