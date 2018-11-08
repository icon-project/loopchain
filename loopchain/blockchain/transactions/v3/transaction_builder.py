import time
from typing import TYPE_CHECKING, Union
from . import Transaction, HASH_SALT
from .. import TransactionBuilder as BaseTransactionBuilder
from ... import Hash32

if TYPE_CHECKING:
    from ... import Address


class TransactionBuilder(BaseTransactionBuilder):
    _hash_salt = HASH_SALT

    def __init__(self, hash_generator_version: int):
        super().__init__(hash_generator_version)

        # Attributes that must be assigned
        self.to_address: 'Address' = None
        self.value: int = None
        self.step_limit: int = None
        self.nid: int = None
        self.nonce: int = None
        self.data: Union[str, dict] = None
        self.data_type: str = None

        # Attributes to be assigned(optional)
        self.fixed_timestamp: int = None

        # Attributes to be generated
        self._timestamp = None

    def reset_cache(self):
        super().reset_cache()
        self._timestamp = None

    def build(self):
        self.build_from_address()
        self.build_hash()
        self.sign()

        return Transaction(
            hash=self.hash,
            signature=self.signature,
            timestamp=self._timestamp,
            from_address=self.from_address,
            to_address=self.to_address,
            value=self.value,
            nid=self.nid,
            step_limit=self.step_limit,
            nonce=self.nonce,
            data_type=self.data_type,
            data=self.data
        )

    def _build_hash(self):
        if self.fixed_timestamp is None:
            self._timestamp = int(time.time() * 1_000_000)
        else:
            self._timestamp = self.fixed_timestamp

        params = {
            "version": "0x3",
            "from": self.from_address.hex_hx(),
            "to": self.to_address.hex_hx(),
            "value": hex(int(self.value)),
            "stepLimit": hex(self.step_limit),
            "timestamp": hex(int(self._timestamp)),
            "nonce": hex(self.nonce),
            "nid": hex(self.nid)
        }
        if self.data is not None and self.data_type is not None:
            if isinstance(self.data, str):
                params["data"] = self.data.encode('utf-8').hex()
            else:
                params["data"] = self.data
            params["dataType"] = self.data_type

        return Hash32(self._hash_generator.generate_hash(params))
