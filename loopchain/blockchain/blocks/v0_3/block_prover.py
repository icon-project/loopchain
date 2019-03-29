import hashlib
from typing import Union, Iterable
from loopchain.blockchain.types import Hash32
from loopchain.blockchain.merkle import MerkleTree
from loopchain.blockchain.blocks import BlockProver as BaseBlockProver, BlockProverType
from loopchain.blockchain.blocks.v0_3 import receipt_hash_generator


class BlockProver(BaseBlockProver):
    def __init__(self, values: Iterable, type_: 'BlockProverType'):
        self.type = type_
        self.hashes = [self.to_hash32(value) for value in values] if values else []
        self._merkle_tree = MerkleTree()

    def get_proof(self, hash_or_index: Union[Hash32, int]) -> list:
        if isinstance(hash_or_index, Hash32):
            index = self.hashes.index(hash_or_index)
        else:
            index = hash_or_index

        if not self._merkle_tree.is_ready:
            self.make_tree()
        return self._merkle_tree.get_proof(index)

    def get_proof_root(self) -> Hash32:
        if not self._merkle_tree.is_ready:
            self.make_tree()
        root = self._merkle_tree.get_merkle_root()
        return Hash32(root) if root is not None else Hash32.empty()

    def prove(self, hash_: Hash32, root_hash: Hash32, proof: list) -> bool:
        return MerkleTree.validate_proof(proof, hash_, root_hash)

    def make_tree(self):
        self._merkle_tree.reset_tree()
        self._merkle_tree.add_leaf(self.hashes)
        self._merkle_tree.make_tree()

    def get_hash_generator(self):
        if self.type == BlockProverType.Block:
            return None  # Do not need
        if self.type == BlockProverType.Transaction:
            return None  # Do not need
        if self.type == BlockProverType.Receipt:
            return receipt_hash_generator
        if self.type == BlockProverType.Rep:
            return None
        if self.type == BlockProverType.Vote:
            return None

    def to_hash32(self, value: Union[Hash32, bytes, bytearray, int, bool, dict]):
        if value is None:
            return Hash32.empty()
        elif isinstance(value, Hash32):
            return value
        elif isinstance(value, (bytes, bytearray)) and len(value) == 32:
            return Hash32(value)

        if isinstance(value, bool):
            value = b'\x01' if value else b'\x00'
        elif isinstance(value, int):
            if value < 0:
                raise RuntimeError(f"value : {value} is negative.")
            value = value.to_bytes((value.bit_length() + 7) // 8, "big")
        elif isinstance(value, dict):
            if self.type == BlockProverType.Receipt:
                value = dict(value)
                value.pop("failure", None)

            hash_generator = self.get_hash_generator()
            value = hash_generator.generate_salted_origin(value)
            value = value.encode()
        return Hash32(hashlib.sha3_256(value).digest())
