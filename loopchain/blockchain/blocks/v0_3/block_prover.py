from typing import List, Union, Iterable
from loopchain.blockchain.merkle import MerkleTree
from .. import BlockProver as BaseBlockProver
from ... import Hash32


class BlockProver(BaseBlockProver):
    def __init__(self, hashes: Union[Iterable[Hash32], List[Hash32]]):
        super().__init__(hashes)
        self._merkle_tree = MerkleTree()

    def get_proof(self, hash_or_index: Union[Hash32, int]) -> list:
        if isinstance(hash_or_index, Hash32):
            if isinstance(self.hashes, List):
                index = self.hashes.index(hash_or_index)
            else:
                raise RuntimeError("self.hashes is not List. Cannot find index of hash")
        else:
            index = hash_or_index

        if not self._merkle_tree.is_ready:
            self.make_tree()
        return self._merkle_tree.get_proof(index)

    def get_proof_root(self) -> Hash32:
        if not self._merkle_tree.is_ready:
            self.make_tree()
        return Hash32(self._merkle_tree.get_merkle_root())

    def prove(self, hash_: Hash32, root_hash: Hash32, proof: list) -> bool:
        if not self._merkle_tree.is_ready:
            self.make_tree()
        return self._merkle_tree.validate_proof(proof, hash_, root_hash)

    def make_tree(self):
        self._merkle_tree.reset_tree()
        self._merkle_tree.add_leaf(self.hashes)
        self._merkle_tree.make_tree()
