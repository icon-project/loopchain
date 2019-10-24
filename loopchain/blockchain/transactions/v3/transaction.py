from dataclasses import dataclass
from typing import Union
from loopchain.blockchain.types import Address, ExternalAddress
from loopchain.blockchain.transactions import Transaction as BaseTransition


@dataclass(frozen=True)
class Transaction(BaseTransition):
    from_address: ExternalAddress
    to_address: Address
    value: int
    nid: int
    step_limit: int
    nonce: int
    data_type: str
    data: Union[str, dict]

    version = "0x3"

    @property
    def signer_address(self) -> 'ExternalAddress':
        return self.from_address

    def type(self):
        return self.data_type


HASH_SALT = "icx_sendTransaction"
