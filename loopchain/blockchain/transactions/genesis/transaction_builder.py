from loopchain.blockchain.transactions import TransactionBuilder as BaseTransactionBuilder
from loopchain.blockchain.transactions.genesis import Transaction, NID, NTxHash, HASH_SALT


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

    def build(self, is_signing=True):
        self.build_origin_data()
        self.build_hash()
        self.build_nid()
        if is_signing:
            self.sign()

        self.build_raw_data(is_signing)
        return Transaction(
            raw_data=self.raw_data,
            hash=self.hash,
            signature=None,
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

    def build_raw_data(self, is_signing=True):
        self.raw_data = dict(self.origin_data)
        if is_signing:
            self.raw_data["signature"] = self.signature.to_base64str()
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

    def sign_transaction(self, tx: 'Transaction'):
        raise NotImplementedError
