import time
from loopchain.blockchain.transactions import TransactionBuilder as BaseTransactionBuilder
from loopchain.blockchain.transactions.v3_issue import Transaction, HASH_SALT


class TransactionBuilder(BaseTransactionBuilder):
    _hash_salt = HASH_SALT

    def __init__(self, hash_generator_version: int):
        super().__init__(hash_generator_version)
        del self.private_key
        del self.from_address
        del self.signature

        # Attributes that must be assigned
        self.nid: int = None
        self.data: dict = None
        self.data_type: str = "issue"

        # Attributes to be assigned(optional)
        self.fixed_timestamp: int = None

        # Attributes to be generated
        self._timestamp = None

    def reset_cache(self):
        super().reset_cache()
        self._timestamp = None

    def build(self):
        self.build_origin_data()
        self.build_hash()
        self.build_raw_data()

        return Transaction(
            raw_data=self.raw_data,
            hash=self.hash,
            timestamp=self._timestamp,
            nid=self.nid,
            data_type=self.data_type,
            data=self.data
        )

    def build_origin_data(self):
        if self.fixed_timestamp is None:
            self._timestamp = int(time.time() * 1_000_000)
        else:
            self._timestamp = self.fixed_timestamp

        self.origin_data = {
            "version": "0x3",
            "timestamp": hex(self._timestamp),
            "nid": hex(self.nid),
            "dataType": self.data_type,
            "data": self.data
        }
        return self.origin_data

    def build_raw_data(self):
        self.raw_data = dict(self.origin_data)
        return self.raw_data
