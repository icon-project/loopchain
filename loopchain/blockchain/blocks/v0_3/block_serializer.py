from collections import OrderedDict

from . import BlockHeader, BlockBody
from .. import Block, BlockSerializer as BaseBlockSerializer
from ... import Hash32, ExternalAddress, Signature, BloomFilter, TransactionSerializer


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
            "prevHash": header.prev_hash.hex() if header.prev_hash else '',
            "transactionHash": header.transaction_hash.hex() if header.transaction_hash else '',
            "stateHash": header.state_hash.hex() if header.state_hash else '',
            "receiptHash": header.receipt_hash.hex() if header.receipt_hash else '',
            "repHash": header.rep_hash.hex(),
            "bloomFilter": header.bloom_filter.hex(),
            "timestamp": header.timestamp,
            "transactions": transactions,
            "hash": header.hash.hex(),
            "height": header.height,
            "leader": header.peer_id.hex_hx() if header.peer_id else '',
            "signature": header.signature.to_base64str() if header.signature else '',
            "nextLeader": header.next_leader.hex_xx(),
            "complained": 1 if header.complained else 0,
        }

    def _deserialize_header_data(self, json_data: dict):
        prev_hash = json_data.get('prevHash')
        prev_hash = Hash32.fromhex(prev_hash, ignore_prefix=True) if prev_hash else None

        peer_id = json_data.get('leader')
        peer_id = ExternalAddress.fromhex(peer_id) if peer_id else None

        signature = json_data.get('signature')
        signature = Signature.from_base64str(signature) if signature else None

        next_leader = json_data.get("nextLeader")
        next_leader = ExternalAddress.fromhex(next_leader) if next_leader else None

        transaction_hash = json_data["transactionHash"]
        transaction_hash = Hash32.fromhex(transaction_hash, ignore_prefix=True) if transaction_hash else None

        receipt_hash = json_data["receiptHash"]
        receipt_hash = Hash32.fromhex(receipt_hash, ignore_prefix=True) if receipt_hash else None

        state_hash = json_data["stateHash"]
        state_hash = Hash32.fromhex(state_hash, ignore_prefix=True) if state_hash else None

        rep_hash = json_data["repHash"]
        rep_hash = Hash32.fromhex(rep_hash, ignore_prefix=True) if state_hash else None

        if json_data["complained"] == 1:
            complained = True
        elif json_data["complained"] == 0:
            complained = False
        else:
            raise RuntimeError

        return {
            "hash": Hash32.fromhex(json_data["hash"], ignore_prefix=True),
            "prev_hash": prev_hash,
            "height": json_data["height"],
            "timestamp": json_data["timestamp"],
            "peer_id": peer_id,
            "signature": signature,
            "next_leader": next_leader,
            "transaction_hash": transaction_hash,
            "receipt_hash": receipt_hash,
            "state_hash": state_hash,
            "rep_hash": rep_hash,
            "bloom_filter": BloomFilter.fromhex(json_data["bloomFilter"], ignore_prefix=True),
            "complained": complained
        }

    def _deserialize_body_data(self, json_data: dict):
        confirm_prev_block = json_data.get("confirmPrevBlock")

        transactions = OrderedDict()
        for tx_data in json_data['transactions']:
            tx_version = self._tx_versioner.get_version(tx_data)
            ts = TransactionSerializer.new(tx_version, self._tx_versioner)
            tx = ts.from_(tx_data)
            transactions[tx.hash] = tx

        return {
            "transactions": transactions,
            "confirm_prev_block": confirm_prev_block
        }
