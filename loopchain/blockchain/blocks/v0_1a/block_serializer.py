from collections import OrderedDict
from . import BlockHeader, BlockBody
from .. import Block, BlockSerializer as BaseBlockSerializer
from ... import ExternalAddress, Signature, Hash32, TransactionSerializer


class BlockSerializer(BaseBlockSerializer):
    version = BlockHeader.version
    BlockHeaderClass = BlockHeader
    BlockBodyClass = BlockBody

    def _serialize(self, block: 'Block'):
        header: BlockHeader = block.header
        body: BlockBody = block.body

        transactions = list()
        for tx in body.transactions.values():
            ts = TransactionSerializer.new(tx.version, self._tx_versioner)
            tx_serialized = ts.to_full_data(tx)
            transactions.append(tx_serialized)

        return {
            "version": header.version,
            "prev_block_hash": header.prev_hash.hex() if header.prev_hash else '',
            "merkle_tree_root_hash": header.merkle_tree_root_hash.hex(),
            "time_stamp": header.timestamp,
            "confirmed_transaction_list": transactions,
            "block_hash": header.hash.hex(),
            "height": header.height,
            "peer_id": header.peer_id.hex_hx() if header.peer_id else '',
            "signature": header.signature.to_base64str() if header.signature else '',
            "next_leader": header.next_leader.hex_xx() if header.next_leader else '',
            "commit_state": header.commit_state
        }

    def _deserialize_header_data(self, json_data: dict):
        prev_hash = json_data.get('prev_block_hash')
        prev_hash = Hash32.fromhex(prev_hash, ignore_prefix=True) if prev_hash else None

        peer_id = json_data.get('peer_id')
        peer_id = ExternalAddress.fromhex(peer_id) if peer_id else None

        signature = json_data.get('signature')
        signature = Signature.from_base64str(signature) if signature else None

        next_leader = json_data.get("next_leader")
        next_leader = ExternalAddress.fromhex(next_leader) if next_leader else None

        return {
            "hash": Hash32.fromhex(json_data["block_hash"], ignore_prefix=True),
            "prev_hash": prev_hash,
            "height": json_data["height"],
            "timestamp": json_data["time_stamp"],
            "peer_id": peer_id,
            "signature": signature,
            "next_leader": next_leader,
            "merkle_tree_root_hash": Hash32.fromhex(json_data["merkle_tree_root_hash"], ignore_prefix=True),
            "commit_state": json_data["commit_state"]
        }

    def _deserialize_body_data(self, json_data: dict):
        confirm_prev_block = json_data.get("confirm_prev_block")

        transactions = OrderedDict()
        for tx_data in json_data['confirmed_transaction_list']:
            tx_version = self._tx_versioner.get_version(tx_data)
            ts = TransactionSerializer.new(tx_version, self._tx_versioner)
            tx = ts.from_(tx_data)
            transactions[tx.hash] = tx

        return {
            "confirm_prev_block": confirm_prev_block,
            "transactions": transactions
        }
