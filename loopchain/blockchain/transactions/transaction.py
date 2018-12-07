import json
from dataclasses import dataclass, _FIELD, _FIELDS
from typing import TYPE_CHECKING
from .. import Hash32, Signature

if TYPE_CHECKING:
    from .. import TransactionVersioner

size_dict_name = "_size_dict"


@dataclass(frozen=True)
class Transaction:
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
        from .. import TransactionSerializer

        if not hasattr(self, size_dict_name):
            object.__setattr__(self, size_dict_name, dict())

        size_dict = getattr(self, size_dict_name)
        hash_generator_version = versioner.get_hash_generator_version(self.version)
        if hash_generator_version not in size_dict:
            ts = TransactionSerializer.new(self.version, versioner)
            tx_serialized = ts.to_full_data(self)
            tx_serialized = json.dumps(tx_serialized)
            tx_serialized = tx_serialized.encode('utf-8')
            size_dict[hash_generator_version] = len(tx_serialized)

        return size_dict[hash_generator_version]
