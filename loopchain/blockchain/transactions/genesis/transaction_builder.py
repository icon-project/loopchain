from . import Transaction, NID, NTxHash, HASH_SALT
from .. import TransactionBuilder as BaseTransactionBuilder
from ... import Hash32


class TransactionBuilder(BaseTransactionBuilder):
    _hash_salt = HASH_SALT

    def __init__(self, hash_generator_version: int):
        super().__init__(hash_generator_version)

        # Attributes that must be assigned
        self.accounts: list = None
        self.message: str = None

        # Attributes to be assigned(optional)
        self.nid: int = None

        # Attributes to be generated
        self.nid_generated: int = None

    def reset_cache(self):
        super().reset_cache()
        self.nid_generated = None

    def build(self):
        self.build_origin_data()
        self.build_hash()
        self.build_nid()

        self.build_raw_data()
        return Transaction(
            raw_data=self.raw_data,
            hash=self.hash,
            timestamp=0,
            nid=self.nid_generated,
            accounts=self.accounts,
            message=self.message
        )

    def build_origin_data(self):
        origin_data = {
            "accounts": self.accounts,
            "message": self.message
        }
        if self.nid is not None:
            origin_data["nid"] = hex(self.nid)
        self.origin_data = origin_data
        return self.origin_data

    def build_raw_data(self):
        self.raw_data = dict(self.origin_data)
        return self.raw_data

    def build_nid(self):
        if self.hash is None:
            raise RuntimeError

        self.nid_generated = self._build_nid()
        return self.nid_generated

    def _build_nid(self):
        if self.nid is not None:
            return self.nid

        if self.hash == NTxHash.mainnet.value:
            return NID.mainnet.value

        if self.hash == NTxHash.testnet.value:
            return NID.testnet.value

        return NID.unknown.value

    def _sign(self):
        return None
