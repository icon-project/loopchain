from dataclasses import dataclass
from typing import Union
from .. import SignedTransaction
from ... import Address


@dataclass(frozen=True)
class Transaction(SignedTransaction):
    from_address: Address
    to_address: Address
    value: int
    nid: int
    step_limit: int
    nonce: int
    data_type: str
    data: Union[str, dict]

    version = "0x3"


HASH_SALT = "icx_sendTransaction"
