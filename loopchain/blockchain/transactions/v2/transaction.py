from dataclasses import dataclass
from .. import Transaction as BaseTransition
from ... import Address
from typing import TYPE_CHECKING, Mapping
from types import MappingProxyType

if TYPE_CHECKING:
    from ... import Hash32, Signature


@dataclass(frozen=True)
class Transaction(BaseTransition):
    from_address: Address
    to_address: Address
    value: str
    fee: str
    nonce: str

    extra: Mapping[str, str]
    method = "icx_sendTransaction"
    version = "0x2"

    def __init__(self, hash: 'Hash32', signature: 'Signature', timestamp: int,
                 from_address: 'Address', to_address: 'Address',
                 value: str, fee: str, nonce: str, extra: Mapping[str, str]):
        super().__init__(hash, signature, timestamp)

        object.__setattr__(self, "from_address", from_address)
        object.__setattr__(self, "to_address", to_address)
        object.__setattr__(self, "value", value)
        object.__setattr__(self, "fee", fee)
        object.__setattr__(self, "nonce", nonce)

        object.__setattr__(self, "extra", dict(extra))


HASH_SALT = "icx_sendTransaction"
