from dataclasses import dataclass
from loopchain.blockchain.transactions import Transaction as BaseTransition


@dataclass(frozen=True)
class Transaction(BaseTransition):
    nid: int
    data_type: str
    data: dict

    # Issue tx is a part of 0x3 tx.
    version = "0x3"


HASH_SALT = "icx_sendTransaction"
