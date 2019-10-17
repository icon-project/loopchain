# Copyright 2019 ICON Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from collections import OrderedDict
from dataclasses import dataclass, _FIELD, _FIELDS
from enum import IntEnum
from types import MappingProxyType
from typing import Mapping

from loopchain.blockchain.transactions import Transaction
from loopchain.blockchain.types import Hash32, ExternalAddress, Signature


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


class NextRepsChangeReason(IntEnum):
    NoChange = -1
    TermEnd = 0
    Penalty = 1

    @classmethod
    def convert_to_change_reason(cls, state: str) -> 'NextRepsChangeReason':
        """Convert next_prep['state'] to NextRepsChangeReason

        :param state: "0x0" is TermEnd,
                      "0x1" is Penalty
        :return: NextRepsChangeReason NoChange, TermEnd, Penalty
        """

        for reason in NextRepsChangeReason:
            if reason.value == int(state, 16):
                return reason

        return NextRepsChangeReason.NoChange
