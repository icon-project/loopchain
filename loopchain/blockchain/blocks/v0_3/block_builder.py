import hashlib
import time
from typing import Union
from . import BlockHeader, BlockBody
from .. import Block, BlockBuilder as BaseBlockBuilder
from ... import Address, Hash32, TransactionVersioner
from ...merkle import MerkleTree


class BlockBuilder(BaseBlockBuilder):
    version = BlockHeader.version
    BlockHeaderClass = BlockHeader
    BlockBodyClass = BlockBody

    def __init__(self, tx_versioner: 'TransactionVersioner'):
        super().__init__(tx_versioner)

        # Attributes that must be assigned
        self.complained = False
        self.next_leader: 'Address' = None

        # Attributes to be assigned(optional)
        self.fixed_timestamp: int = None
        self.state_root_hash: 'Hash32' = None

        # Attributes to be generated
        self.transaction_root_hash: 'Hash32' = None

        self._timestamp: int = None

    def reset_cache(self):
        super().reset_cache()
        self.complained = False
        self.next_leader: 'Address' = None

        self.transaction_root_hash: 'Hash32' = None
        self.state_root_hash: 'Hash32' = None

    def build(self):
        if self.height > 0:
            self.build_peer_id()
            self.build_transaction_root_hash()
            self.build_hash()
            self.sign()
        else:
            self.build_transaction_root_hash()
            self.build_hash()

        self.block = self.build_block()
        return self.block

    def build_block_header_data(self) -> dict:
        return {
            "hash": self.hash,
            "prev_hash": self.prev_hash,
            "height": self.height,
            "timestamp": self._timestamp,
            "peer_id": self.peer_id,
            "signature": self.signature,
            "next_leader": self.next_leader,
            "transaction_root_hash": self.transaction_root_hash,
            "state_root_hash": self.state_root_hash,
            "complained": self.complained
        }

    def build_block_body_data(self) -> dict:
        return {
            "transactions": self.transactions,
        }

    def build_transaction_root_hash(self):
        if self.transaction_root_hash is not None:
            return self.transaction_root_hash

        self.transaction_root_hash = self._build_transaction_root_hash()
        return self.transaction_root_hash

    def _build_transaction_root_hash(self):
        merkle = MerkleTree()
        merkle.add_leaf(self.transactions.keys())
        merkle.make_tree()
        return Hash32(merkle.get_merkle_root())

    def build_hash(self):
        if self.hash is not None:
            return self.hash

        if self.height > 0 and self.prev_hash is None:
            raise RuntimeError

        self.build_transaction_root_hash()
        self.hash = self._build_hash()
        return self.hash

    def _build_hash(self):
        if self.fixed_timestamp is not None:
            self._timestamp = self.fixed_timestamp
        else:
            self._timestamp = int(time.time() * 1_000_000)

        leaves = (
            self.prev_hash,
            self.transaction_root_hash,
            self.height,
            self._timestamp,
            self.peer_id,
            self.next_leader,
            self.complained
        )
        leaves = [self._to_hash32(leaf) for leaf in leaves if leaf is not None]

        merkle = MerkleTree()
        merkle.add_leaf(leaves)
        merkle.make_tree()
        return Hash32(merkle.get_merkle_root())

    @classmethod
    def _to_hash32(cls, value: Union[Hash32, bytes, bytearray, int, bool]):
        if isinstance(value, Hash32):
            return value
        if isinstance(value, (bytes, bytearray)) and len(value) == 32:
            return Hash32(value)

        if isinstance(value, bool):
            value = b'\x01' if value else b'\x00'
        elif isinstance(value, int):
            if value < 0:
                raise RuntimeError(f"value : {value} is negative.")
            value = value.to_bytes((value.bit_length() + 7) // 8, "big")
        return Hash32(hashlib.sha3_256(value).digest())

    def from_(self, block: 'Block'):
        super().from_(block)

        header: BlockHeader = block.header
        self.next_leader = header.next_leader
        self.state_root_hash = header.state_root_hash
        self.transaction_root_hash = header.transaction_root_hash
        self.fixed_timestamp = header.timestamp
        self.complained = header.complained
        self._timestamp = header.timestamp
