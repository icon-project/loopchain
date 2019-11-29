from loopchain.blockchain.types import ExternalAddress
from loopchain.blockchain.transactions import TransactionVerifier as BaseTransactionVerifier
from loopchain.blockchain.transactions.genesis import Transaction, TransactionSerializer, HASH_SALT


class TransactionVerifier(BaseTransactionVerifier):
    _hash_salt = HASH_SALT
    _allow_unsigned = True

    def __init__(self, hash_generator_version: int, raise_exceptions=True):
        super().__init__(hash_generator_version, raise_exceptions)
        self._tx_serializer = TransactionSerializer(hash_generator_version)

    def pre_verify(self, tx: 'Transaction', **kwargs):
        raise RuntimeError("Genesis Tx pre verify cannot be called.")

    def verify(self, tx: 'Transaction', blockchain=None, tx_tx=None):
        self.verify_loosely(tx, blockchain)

    def verify_loosely(self, tx: 'Transaction', blockchain=None, db_tx=None):
        self.verify_hash(tx)
        self.verify_signature(tx)
        self.verify_accounts(tx)
        if blockchain:
            self.verify_empty_blockchain(tx, blockchain)
            self.verify_tx_hash_unique(tx, blockchain)

    def verify_accounts(self, tx: 'Transaction'):
        for account in tx.accounts:
            if "address" not in account:
                raise RuntimeError(f'Genesis Tx({tx.hash.hex()}), '
                                   f'"address" does not exist in an account of genesis tx.')
            if "balance" not in account:
                raise RuntimeError(f'Genesis Tx({tx.hash.hex()}), '
                                   f'"balance" does not exist in an account of genesis tx.')
            if "name" not in account:
                raise RuntimeError(f'Genesis Tx({tx.hash.hex()}), '
                                   f'"name" does not exist in an account of genesis tx.')

            if account["balance"] is None:
                raise RuntimeError(f'Genesis Tx({tx.hash.hex()}), '
                                   '"balance" value is None in an account of genesis tx.')

            # An exception will be raised if 'address' is invalid.
            ExternalAddress.fromhex(account['address'])

    def verify_empty_blockchain(self, tx: 'Transaction', blockchain):
        if blockchain.block_height >= 0:
            raise RuntimeError(f'Genesis Tx({tx.hash.hex()}), '
                               f"Genesis Tx cannot be added blockchain height {blockchain.block_height}.")
