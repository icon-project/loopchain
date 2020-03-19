import time
from typing import TYPE_CHECKING
from legacy.blockchain.transactions import TransactionBuilder as BaseTransactionBuilder
from legacy.blockchain.transactions.v2 import Transaction, HASH_SALT
from legacy.blockchain.types import Signature

if TYPE_CHECKING:
    from legacy.blockchain.types import Address


ICX_FEE = int(0.01 * 10**18)


class TransactionBuilder(BaseTransactionBuilder):
    _hash_salt = HASH_SALT

    def __init__(self, hash_generator_version: int):
        super().__init__(hash_generator_version)

        # Attributes that must be assigned
        self.to_address: 'Address' = None
        self.value: int = None
        self.fee: int = ICX_FEE
        self.nonce: int = None

        # Attributes to be assigned(optional)
        self.fixed_timestamp: int = None

        # Attributes to be generated
        self._timestamp = None

    def reset_cache(self):
        super().reset_cache()
        self._timestamp = None

    def build(self, is_signing=True):
        self.build_from_address()
        self.build_origin_data()
        self.build_hash()
        if is_signing:
            self.sign()
        self.build_raw_data(is_signing)

        return Transaction(
            raw_data=self.raw_data,
            hash=self.hash,
            signature=self.signature,
            timestamp=self._timestamp,
            from_address=self.from_address,
            to_address=self.to_address,
            value=self.value,
            fee=self.fee,
            nonce=self.nonce
        )

    def build_origin_data(self):
        if self.fixed_timestamp is None:
            self._timestamp = int(time.time() * 1_000_000)
        else:
            self._timestamp = self.fixed_timestamp

        origin_data = {
            "from": self.from_address.hex_xx(),
            "to": self.to_address.hex_xx(),
            "value": hex(self.value),
            "fee": hex(self.fee),
            "timestamp": str(self._timestamp)
        }
        if self.nonce is not None:
            origin_data["nonce"] = str(self.nonce)

        self.origin_data = origin_data
        return self.origin_data

    def build_raw_data(self, is_signing=True):
        raw_data = dict(self.origin_data)
        raw_data["tx_hash"] = self.hash.hex()
        if is_signing:
            raw_data["signature"] = self.signature.to_base64str()
        self.raw_data = raw_data
        return self.raw_data

    def sign_transaction(self, tx: 'Transaction'):
        if self.signer.address != tx.signer_address.hex_hx():
            raise RuntimeError(f"Signer not match. {self.signer.address} != {tx.signer_address.hex_hx()}")

        signature = Signature(self.signer.sign_hash(tx.hash))

        raw_data = dict(tx.raw_data)
        raw_data["signature"] = signature.to_base64str()

        return Transaction(
            raw_data=raw_data,
            hash=tx.hash,
            signature=signature,
            timestamp=tx.timestamp,
            from_address=tx.from_address,
            to_address=tx.to_address,
            value=tx.value,
            fee=tx.fee,
            nonce=tx.nonce
        )