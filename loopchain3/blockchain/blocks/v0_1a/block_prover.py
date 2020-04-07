from typing import Union
from loopchain.blockchain.types import Hash32
from loopchain.blockchain.blocks import BlockProver as BaseBlockProver
from loopchain.blockchain.blocks.v0_1a import BlockHeader


class BlockProver(BaseBlockProver):
    version = BlockHeader.version

    def get_proof(self, hash_: Hash32):
        raise RuntimeError(f"get_proof: Not supported ver: {self.version}")

    def get_proof_root(self):
        raise RuntimeError(f"get_proof_root: Not supported ver: {self.version}")

    def prove(self, hash_: Hash32, root_hash: Hash32, proof: list):
        raise RuntimeError(f"prove: Not supported ver: {self.version}")

    def get_hash_generator(self):
        raise RuntimeError(f"get_hash_generator: Not supported ver: {self.version}")

    def to_hash32(self, value: Union[Hash32, bytes, bytearray, int, bool, dict]):
        raise RuntimeError(f"to_hash32: Not supported ver: {self.version}")
