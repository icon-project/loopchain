import json
from dataclasses import dataclass
from .. import Hash32, Signature

length_attr_name = "_length"


@dataclass(frozen=True)
class Transaction:
    hash: Hash32
    signature: Signature
    timestamp: int

    version = ''

    def __len__(self):
        if not hasattr(self, length_attr_name):
            from . import TransactionSerializer, TransactionVersions

            tv = TransactionVersions()
            hash_version = tv.get_hash_generator_version(self.version)

            ts = TransactionSerializer.new(self.version, hash_version)
            tx_serialized = ts.serialize(self)
            tx_serialized = json.dumps(tx_serialized)
            tx_serialized = tx_serialized.encode('utf-8')

            object.__setattr__(self, length_attr_name, len(tx_serialized))

        return getattr(self, length_attr_name)
