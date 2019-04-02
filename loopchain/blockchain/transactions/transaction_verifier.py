import hashlib

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING
from secp256k1 import PublicKey, PrivateKey
from loopchain.crypto.hashing import build_hash_generator
from loopchain.blockchain.types import Hash32, ExternalAddress

if TYPE_CHECKING:
    from loopchain.blockchain.transactions import Transaction, TransactionVersioner


class TransactionVerifier(ABC):
    _ecdsa = PrivateKey()
    _hash_salt = None

    def __init__(self, hash_generator_version: int):
        self._hash_generator = build_hash_generator(hash_generator_version, self._hash_salt)
        self._tx_serializer = None

    @abstractmethod
    def verify(self, tx: 'Transaction', blockchain=None):
        raise NotImplementedError

    @abstractmethod
    def verify_loosely(self, tx: 'Transaction', blockchain=None):
        raise NotImplementedError

    def verify_tx_hash_unique(self, tx: 'Transaction', blockchain):
        if blockchain.find_tx_by_key(tx.hash.hex()):
            raise RuntimeError(f"tx({tx})\n"
                               f"hash {tx.hash.hex()} already exists in blockchain.")

    def verify_hash(self, tx: 'Transaction'):
        params = self._tx_serializer.to_origin_data(tx)
        tx_hash_expected = self._hash_generator.generate_hash(params)
        if tx_hash_expected != tx.hash:
            raise RuntimeError(f"tx({tx})\n"
                               f"hash {tx.hash.hex()}\n"
                               f"expected {Hash32(tx_hash_expected).hex()}")

    def verify_signature(self, tx: 'Transaction'):
        recoverable_sig = self._ecdsa.ecdsa_recoverable_deserialize(
            tx.signature.signature(),
            tx.signature.recover_id())
        raw_public_key = self._ecdsa.ecdsa_recover(tx.hash,
                                                   recover_sig=recoverable_sig,
                                                   raw=True,
                                                   digest=hashlib.sha3_256)

        public_key = PublicKey(raw_public_key, ctx=self._ecdsa.ctx)
        hash_pub = hashlib.sha3_256(public_key.serialize(compressed=False)[1:]).digest()
        expect_address = hash_pub[-20:]
        if expect_address != tx.from_address:
            raise RuntimeError(f"tx({tx})\n"
                               f"from address {tx.from_address.hex_xx()}\n"
                               f"expected {ExternalAddress(expect_address).hex_xx()}")

    @classmethod
    def new(cls, version: str, versioner: 'TransactionVersioner'):
        hash_generator_version = versioner.get_hash_generator_version(version)

        from . import v3
        if version == v3.version:
            return v3.TransactionVerifier(hash_generator_version)

        from . import v2
        if version == v2.version:
            return v2.TransactionVerifier(hash_generator_version)

        from . import genesis
        if version == genesis.version:
            return genesis.TransactionVerifier(hash_generator_version)

        raise RuntimeError(f"Not supported tx version({version})")
