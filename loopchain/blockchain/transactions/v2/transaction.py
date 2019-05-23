from dataclasses import dataclass
from typing import Mapping, Union
from loopchain.blockchain.types import Address, MalformedStr, Hash32, Signature, ExternalAddress
from loopchain.blockchain.transactions import Transaction as BaseTransition


@dataclass(frozen=True)
class Transaction(BaseTransition):
    from_address: ExternalAddress
    to_address: ExternalAddress
    value: Union[int, MalformedStr]
    fee: Union[int, MalformedStr]
    nonce: Union[int, MalformedStr]

    extra: Mapping[str, str]
    method = "icx_sendTransaction"
    version = "0x2"

    def __init__(self, raw_data: dict, hash: 'Hash32', signature: 'Signature', timestamp: int,
                 from_address: 'Address', to_address: 'Address',
                 value: Union[int, MalformedStr], fee: Union[int, MalformedStr], nonce: Union[int, MalformedStr],
                 extra: Mapping[str, str]):
        super().__init__(raw_data, hash, signature, timestamp)

        object.__setattr__(self, "from_address", from_address)
        object.__setattr__(self, "to_address", to_address)
        object.__setattr__(self, "value", value)
        object.__setattr__(self, "fee", fee)
        object.__setattr__(self, "nonce", nonce)

        object.__setattr__(self, "extra", dict(extra))

    @property
    def signer(self) -> 'ExternalAddress':
        return self.from_address


HASH_SALT = "icx_sendTransaction"
