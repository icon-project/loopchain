from collections import OrderedDict

from loopchain.blockchain.types import Hash32, ExternalAddress, Signature, BloomFilter
from loopchain.blockchain.transactions import TransactionSerializer
from loopchain.blockchain.blocks import Block, BlockSerializer as BaseBlockSerializer
from loopchain.blockchain.blocks.v0_3 import BlockHeader, BlockBody


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
            "prevHash": header.prev_hash.hex_0x() if header.prev_hash else '',
            "transactionHash": header.transaction_hash.hex_0x() if header.transaction_hash else '',
            "stateHash": header.state_hash.hex_0x() if header.state_hash else '',
            "receiptHash": header.receipt_hash.hex_0x() if header.receipt_hash else '',
            "repHash": header.rep_hash.hex_0x(),
            "bloomFilter": header.bloom_filter.hex_0x(),
            "timestamp": hex(header.timestamp),
            "transactions": transactions,
            "hash": header.hash.hex_0x(),
            "height": hex(header.height),
            "leader": header.peer_id.hex_hx() if header.peer_id else '',
            "signature": header.signature.to_base64str() if header.signature else '',
            "nextLeader": header.next_leader.hex_xx(),
            "complained": "0x1" if header.complained else "0x0",
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

        transaction_hash = json_data["transactionHash"]
        transaction_hash = Hash32.fromhex(transaction_hash) if transaction_hash else None

        receipt_hash = json_data["receiptHash"]
        receipt_hash = Hash32.fromhex(receipt_hash) if receipt_hash else None

        state_hash = json_data["stateHash"]
        state_hash = Hash32.fromhex(state_hash) if state_hash else None

        rep_hash = json_data["repHash"]
        rep_hash = Hash32.fromhex(rep_hash) if state_hash else None

        height = json_data["height"]
        height = int(height, 16)

        timestamp = json_data["timestamp"]
        timestamp = int(timestamp, 16)

        if json_data["complained"] == "0x1":
            complained = True
        elif json_data["complained"] == "0x0":
            complained = False
        else:
            raise RuntimeError

        return {
            "hash": hash_,
            "prev_hash": prev_hash,
            "height": height,
            "timestamp": timestamp,
            "peer_id": peer_id,
            "signature": signature,
            "next_leader": next_leader,
            "transaction_hash": transaction_hash,
            "receipt_hash": receipt_hash,
            "state_hash": state_hash,
            "rep_hash": rep_hash,
            "bloom_filter": BloomFilter.fromhex(json_data["bloomFilter"]),
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
