import hashlib
import time
from typing import Union
from merkletools import MerkleTools
from . import BlockHeader, BlockBody
from .. import BlockBuilder as BaseBlockBuilder
from ... import Address, Hash32, TransactionVersioner


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
        merkle = MerkleTools(hash_type="sha3_256")
        merkle.add_leaf(
            list(map(lambda tx_hash: tx_hash.hex(), self.transactions))
        )
        merkle.make_tree()
        return Hash32(bytes.fromhex(merkle.get_merkle_root()))

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
        leaves = [self._to_bytes32_str(leaf) for leaf in leaves if leaf is not None]

        merkle = MerkleTools(hash_type="sha3_256")
        merkle.add_leaf(leaves)
        merkle.make_tree()
        return Hash32(bytes.fromhex(merkle.get_merkle_root()))

    @classmethod
    def _to_bytes32_str(cls, value: Union[int, bool, Hash32, Address]):
        if isinstance(value, Hash32):
            return value.hex()
        if isinstance(value, bool):
            value = b'\x01' if value else b'\x00'
            return hashlib.sha3_256(value).hexdigest()
        if isinstance(value, int):
            if value < 0:
                raise RuntimeError(f"value : {value} is negative.")
            value = value.to_bytes((value.bit_length() + 7) // 8, "big")
            return hashlib.sha3_256(value).hexdigest()
        if isinstance(value, Address):
            return hashlib.sha3_256(value).hexdigest()

        raise RuntimeError(f"Cannot encode to byte32 str {type(value)}:{value}")
