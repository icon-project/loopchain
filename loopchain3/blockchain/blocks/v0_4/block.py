from dataclasses import dataclass
from typing import Optional

from loopchain.blockchain.blocks import NextRepsChangeReason, v0_3
from loopchain.blockchain.types import ExternalAddress
from loopchain.crypto.hashing import build_hash_generator


@dataclass(frozen=True)
class BlockHeader(v0_3.BlockHeader):

    version = "0.4"

    @property
    def prep_changed_reason(self) -> Optional[NextRepsChangeReason]:
        """Return prep changed reason

        :return: NextRepsChangeReason : NoChange, TermEnd, Penalty
        """
        if not self.prep_changed and not self.is_unrecorded:
            return NextRepsChangeReason.NoChange

        if self.next_leader == ExternalAddress.empty():
            return NextRepsChangeReason.TermEnd

        return NextRepsChangeReason.Penalty


BlockBody = v0_3.BlockBody
# receipts_hash_generator = build_hash_generator(1, "icx_receipt")
