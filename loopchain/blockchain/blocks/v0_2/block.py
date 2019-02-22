from dataclasses import dataclass
from .. import v0_1a


@dataclass(frozen=True)
class BlockHeader(v0_1a.BlockHeader):
    complained: bool

    version = "0.2"

    @property
    def is_complained(self):
        return self.complained


@dataclass(frozen=True)
class BlockBody(v0_1a.BlockBody):
    pass
