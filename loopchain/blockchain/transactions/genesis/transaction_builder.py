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
        self.build_hash()
        self.build_nid()

        return Transaction(
            hash=self.hash,
            signature=None,
            timestamp=0,
            nid=self.nid_generated,
            accounts=self.accounts,
            message=self.message
        )

    def build_hash(self):
        if self.accounts is None:
            raise RuntimeError

        if self.message is None:
            raise RuntimeError

        self.hash = self._build_hash()
        return self.hash

    def _build_hash(self):
        params = {
            "accounts": self.accounts,
            "message": self.message
        }
        if self.nid is not None:
            params["nid"] = hex(self.nid)

        return Hash32(self._hash_generator.generate_hash(params))

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
