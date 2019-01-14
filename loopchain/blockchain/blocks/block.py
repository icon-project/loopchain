from collections import OrderedDict
from dataclasses import dataclass, _FIELD, _FIELDS
from types import MappingProxyType
from typing import Mapping
from .. import Hash32, ExternalAddress, Signature
from ..transactions import Transaction


@dataclass(frozen=True)
class BlockHeader:
    hash: Hash32
    prev_hash: Hash32
    height: int
    timestamp: int
    peer_id: ExternalAddress
    signature: Signature

    version = ''


@dataclass(frozen=True)
class BlockBody:
    transactions: Mapping[Hash32, Transaction]

    # TODO: Make sure that subclass of `BlockBody` call `BlockBody.__init__`
    def __init__(self, transactions: Mapping[Hash32, Transaction]):
        transactions = OrderedDict(transactions)
        transactions.__str__ = _dict__str__

        object.__setattr__(self, "transactions", MappingProxyType(transactions))


@dataclass(frozen=True)
class Block:
    header: BlockHeader
    body: BlockBody


def _dataclass__str__(self):
    fields = getattr(self, _FIELDS, None)
    if fields is None:
        return ""

    fields = [f for f in fields.values() if f._field_type is _FIELD]
    fields_str = ', '.join(f"{f.name}={getattr(self, f.name)}" for f in fields)
    return f"{self.__class__.__qualname__}({fields_str})"


def _dict__str__(self: dict):
    return '{0.__class__.__name__}({0._mapping})'.format(self)


BlockHeader.__str__ = _dataclass__str__
BlockBody.__str__ = _dataclass__str__
Block.__str__ = _dataclass__str__
