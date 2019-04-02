from collections import OrderedDict

from dataclasses import dataclass
from loopchain.blockchain.types import Hash32, Address, Signature, ExternalAddress
from loopchain.blockchain.blocks import BlockHeader as BaseBlockHeader, BlockBody as BaseBlockBody, _dict__str__


@dataclass(frozen=True)
class BlockHeader(BaseBlockHeader):
    next_leader: Address
    merkle_tree_root_hash: Hash32
    commit_state: dict

    version = "0.1a"

    def __init__(self, hash: Hash32, prev_hash: Hash32, height: int, timestamp: int, peer_id: ExternalAddress,
                 signature: Signature, next_leader: Address, merkle_tree_root_hash: Hash32, commit_state: dict):
        super().__init__(hash, prev_hash, height, timestamp, peer_id, signature)

        object.__setattr__(self, "next_leader", next_leader)
        object.__setattr__(self, "merkle_tree_root_hash", merkle_tree_root_hash)

        if commit_state is None:
            object.__setattr__(self, "commit_state", commit_state)
        else:
            commit_state = OrderedDict(commit_state)
            commit_state.__str__ = _dict__str__
            object.__setattr__(self, "commit_state", commit_state)

    @property
    def complained(self) -> bool:
        # tx == 0 and peer_id == next_leader >> complained = True
        return self.peer_id == self.next_leader and self.merkle_tree_root_hash == Hash32(bytes(32))


@dataclass(frozen=True)
class BlockBody(BaseBlockBody):
    confirm_prev_block: bool
