from . import BlockHeader
from .. import BlockProver as BaseBlockProver
from ... import Hash32


class BlockProver(BaseBlockProver):
    version = BlockHeader.version

    def get_proof(self, hash_: Hash32):
        raise RuntimeError(f"get_proof: Not supported ver: {self.version}")

    def get_proof_root(self):
        raise RuntimeError(f"get_proof_root: Not supported ver: {self.version}")

    def prove(self, hash_: Hash32, root_hash: Hash32, proof: list):
        raise RuntimeError(f"prove: Not supported ver: {self.version}")
