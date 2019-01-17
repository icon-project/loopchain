import json
from dataclasses import dataclass, _FIELD, _FIELDS
from typing import TYPE_CHECKING
from .. import Hash32, Signature

if TYPE_CHECKING:
    from .. import TransactionVersioner

_size_attr_name_ = "_size_attr_"


@dataclass(frozen=True)
class Transaction:
    # TODO wrap `raw_data` to `MappingProxy`
    raw_data: dict

    hash: Hash32
    signature: Signature
    timestamp: int

    version = ''

    def __str__(self):
        fields = getattr(self, _FIELDS, None)
        if fields is None:
            return ""

        fields = [f for f in fields.values() if f._field_type is _FIELD]
        fields_str = ', '.join(f"{f.name}={getattr(self, f.name)}" for f in fields)
        return f"{self.__class__.__qualname__}({fields_str})"

    def size(self, versioner: 'TransactionVersioner'):
        if not hasattr(self, _size_attr_name_):
            from .. import TransactionSerializer
            ts = TransactionSerializer.new(self.version, versioner)
            tx_serialized = ts.to_full_data(self)
            tx_serialized = json.dumps(tx_serialized)
            tx_serialized = tx_serialized.encode('utf-8')
            object.__setattr__(self, _size_attr_name_, len(tx_serialized))

        return getattr(self, _size_attr_name_)
