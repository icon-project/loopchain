from dataclasses import dataclass
from .. import Transaction as BaseTransition
from ... import Address


@dataclass(frozen=True)
class Transaction(BaseTransition):
    from_address: Address
    to_address: Address
    value: str
    fee: str
    nonce: str

    method = "icx_sendTransaction"
    version = "0x2"


HASH_SALT = "icx_sendTransaction"
