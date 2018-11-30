from enum import IntEnum, Enum
from dataclasses import dataclass
from typing import TYPE_CHECKING, Union
from .. import Transaction as BaseTransition
from ... import Hash32

if TYPE_CHECKING:
    from ... import Signature


@dataclass(frozen=True)
class Transaction(BaseTransition):
    nid: int
    accounts: tuple
    message: str

    version = "genesis"

    def __init__(self, hash: 'Hash32', signature: Union['Signature', None], timestamp: int,
                 nid: int, accounts: list, message: str):
        super().__init__(hash, signature, timestamp)

        object.__setattr__(self, "nid", nid)
        object.__setattr__(self, "accounts", tuple(accounts))
        object.__setattr__(self, "message", message)


class NTxHash(Enum):
    mainnet = Hash32.fromhex("5aa2453a84ba2fb1e3394b9e3471f5dcebc6225fc311a97ca505728153b9d246")
    testnet = Hash32.fromhex("5a7ce1e10a6fd5fb3925a011528f89a5debfead2405f5545a99d1a1310e48c9e")


class NID(IntEnum):
    mainnet = 1
    testnet = 2
    unknown = 3


HASH_SALT = "genesis_tx"
