import hashlib
import struct
import time
from typing import TYPE_CHECKING

from . import BlockHeader, BlockBody
from .. import Block, BlockBuilder as BaseBlockBuilder
from ... import Hash32, Address

if TYPE_CHECKING:
    from ... import TransactionVersioner


class BlockBuilder(BaseBlockBuilder):
    version = BlockHeader.version
    BlockHeaderClass = BlockHeader
    BlockBodyClass = BlockBody

    def __init__(self, tx_versioner: 'TransactionVersioner'):
        super().__init__(tx_versioner)

        # Attributes to be assigned(optional)
        self.next_leader: Address = None
        self.confirm_prev_block = True
        self.fixed_timestamp: int = None

        # Attributes to be generated
        self.commit_state: dict = None
        self.merkle_tree_root_hash: 'Hash32' = None

        self._timestamp: int = None

    def reset_cache(self):
        super().reset_cache()

        self.merkle_tree_root_hash = None
        self.commit_state = None
        self._timestamp = None

    def build(self):
        self.build_merkle_tree_root_hash()
        self.build_hash()

        if self.height > 0:
            self.build_peer_id()
            self.sign()

        self.block = self.build_block()
        return self.block

    def build_block_header_data(self):
        return {
            "hash": self.hash,
            "prev_hash": self.prev_hash,
            "height": self.height,
            "timestamp": self._timestamp,
            "peer_id": self.peer_id,
            "signature": self.signature,
            "next_leader": self.next_leader,
            "merkle_tree_root_hash": self.merkle_tree_root_hash,
            "commit_state": self.commit_state
        }

    def build_block_body_data(self):
        return {
            "transactions": self.transactions,
            "confirm_prev_block": self.confirm_prev_block
        }

    def build_merkle_tree_root_hash(self):
        if self.merkle_tree_root_hash is not None:
            return self.merkle_tree_root_hash

        self.merkle_tree_root_hash = self._build_merkle_tree_root_hash()
        return self.merkle_tree_root_hash

    def _build_merkle_tree_root_hash(self):
        merkle_tree_root_hash = None
        mt_list = [tx_hash.hex() for tx_hash in self.transactions.keys()]

        while True:
            tree_length = len(mt_list)
            tmp_mt_list = []
            if tree_length <= 1:
                break
            elif tree_length % 2 == 1:
                mt_list.append(mt_list[tree_length-1])
                tree_length += 1

            for row in range(int(tree_length/2)):
                idx = row * 2
                mt_nodes = [mt_list[idx].encode(encoding='UTF-8'), mt_list[idx+1].encode(encoding='UTF-8')]
                mk_sum = b''.join(mt_nodes)
                mk_hash = hashlib.sha256(mk_sum).hexdigest()
                tmp_mt_list.append(mk_hash)
            mt_list = tmp_mt_list

        if len(mt_list) == 1:
            merkle_tree_root_hash = mt_list[0]

        if merkle_tree_root_hash:
            return Hash32.fromhex(merkle_tree_root_hash, True)

        return Hash32(bytes(Hash32.size))

    def build_hash(self):
        if self.hash is not None:
            return self.hash

        if self.height > 0 and self.prev_hash is None:
            raise RuntimeError

        if self.merkle_tree_root_hash is None:
            self.build_merkle_tree_root_hash()

        self.hash = self._build_hash()
        return self.hash

    def _build_hash(self):
        if self.fixed_timestamp is not None:
            self._timestamp = self.fixed_timestamp
        else:
            self._timestamp = int(time.time() * 1_000_000)

        block_hash_data = b''
        if self.prev_hash is not None:
            block_hash_data += self.prev_hash.hex().encode(encoding='UTF-8')
        block_hash_data += self.merkle_tree_root_hash.hex().encode(encoding='UTF-8')
        block_hash_data += struct.pack('Q', self._timestamp)

        return Hash32(hashlib.sha3_256(block_hash_data).digest())

    def from_(self, block: 'Block'):
        super().from_(block)

        header: BlockHeader = block.header
        self.next_leader = header.next_leader
        self.commit_state = header.commit_state
        self.merkle_tree_root_hash = header.merkle_tree_root_hash
        self.fixed_timestamp = header.timestamp

        self._timestamp = header.timestamp

        body: BlockBody = block.body
        self.confirm_prev_block = body.confirm_prev_block

    def get_vote_result(self, block_info):
        return b'0x1'
