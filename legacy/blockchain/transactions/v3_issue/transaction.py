from dataclasses import dataclass
from typing import Union
from legacy.blockchain import ExternalAddress
from legacy.blockchain.transactions import Transaction as BaseTransition


@dataclass(frozen=True)
class Transaction(BaseTransition):
    data_type: str  # issue
    data: Union[str, dict]

    version = "0x3"

    @property
    def signer_address(self) -> 'ExternalAddress':
        raise NotImplementedError

    def type(self):
        return self.data_type


HASH_SALT = "icx_sendTransaction"
