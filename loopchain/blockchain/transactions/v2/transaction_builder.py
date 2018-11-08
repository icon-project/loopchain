import time
from typing import TYPE_CHECKING
from . import Transaction, HASH_SALT
from .. import TransactionBuilder as BaseTransactionBuilder
from ... import Hash32

if TYPE_CHECKING:
    from ... import Address


ICX_FEE = int(0.01 * 10**18)


class TransactionBuilder(BaseTransactionBuilder):
    _hash_salt = HASH_SALT

    def __init__(self, hash_generator_version: int):
        super().__init__(hash_generator_version)

        # Attributes that must be assigned
        self.to_address: 'Address' = None
        self.value: int = None
        self.fee: int = ICX_FEE
        self.nonce = None

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
            fee=self.fee,
            nonce=self.nonce
        )

    def _build_hash(self):
        if self.fixed_timestamp is None:
            self._timestamp = int(time.time() * 1_000_000)
        else:
            self._timestamp = self.fixed_timestamp

        params = {
            "from": self.from_address.hex_hx(),
            "to": self.to_address.hex_hx(),
            "value": hex(self.value),
            "fee": hex(self.fee),
            "timestamp": str(self._timestamp)
        }
        if self.nonce is not None:
            params["nonce"] = hex(self.nonce)

        return Hash32(self._hash_generator.generate_hash(params))
