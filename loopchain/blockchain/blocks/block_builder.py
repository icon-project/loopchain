import hashlib
from abc import ABC, abstractmethod
from collections import OrderedDict
from typing import Dict

from secp256k1 import PrivateKey

from . import Block
from .. import Hash32, ExternalAddress, Signature
from ..transactions import Transaction, TransactionVersioner


class BlockBuilder(ABC):
    version = None
    BlockHeaderClass = None
    BlockBodyClass = None

    def __init__(self, tx_versioner: 'TransactionVersioner'):
        # Attributes that must be assigned
        self.height: int = None
        self.prev_hash: 'Hash32' = None
        self.peer_private_key: 'PrivateKey' = None

        self.transactions: Dict['Hash32', 'Transaction'] = OrderedDict()

        # Attributes to be generated
        self.block: Block = None
        self.hash: Hash32 = None
        self.signature: Signature = None
        self.peer_id: 'ExternalAddress' = None

        self._tx_versioner = tx_versioner

    def size(self):
        return sum(tx.size(self._tx_versioner) for tx in self.transactions.values())

    def reset_cache(self):
        self.block = None
        self.hash = None
        self.signature = None
        self.peer_id = None

    def build(self) -> 'Block':
        raise NotImplementedError

    def build_block(self):
        header = self.BlockHeaderClass(**self.build_block_header_data())
        body = self.BlockBodyClass(**self.build_block_body_data())
        return Block(header, body)

    @abstractmethod
    def build_block_header_data(self) -> dict:
        raise NotImplementedError

    @abstractmethod
    def build_block_body_data(self) -> dict:
        raise NotImplementedError

    def build_hash(self):
        if self.prev_hash is None:
            raise RuntimeError

        self.hash = self._build_hash()
        return self.hash

    def _build_hash(self):
        raise NotImplementedError

    def build_peer_id(self):
        if self.peer_id is not None:
            return self.peer_id

        if self.peer_private_key is None:
            raise RuntimeError

        self.peer_id = self._build_peer_id()
        return self.peer_id

    def _build_peer_id(self):
        serialized_pub = self.peer_private_key.pubkey.serialize(compressed=False)
        hashed_pub = hashlib.sha3_256(serialized_pub[1:]).digest()
        return ExternalAddress(hashed_pub[-20:])

    def sign(self):
        if self.signature is not None:
            return self.signature

        if self.hash is None:
            raise RuntimeError

        self.signature = self._sign()
        return self.signature

    def _sign(self):
        raw_sig = self.peer_private_key.ecdsa_sign_recoverable(msg=self.hash,
                                                               raw=True,
                                                               digest=hashlib.sha3_256)
        serialized_sig, recover_id = self.peer_private_key.ecdsa_recoverable_serialize(raw_sig)
        signature = serialized_sig + bytes((recover_id, ))
        return Signature(signature)

    @classmethod
    def new(cls, version: str, tx_versioner: 'TransactionVersioner'):
        from . import v0_1a
        if version == v0_1a.version:
            return v0_1a.BlockBuilder(tx_versioner)

        raise NotImplementedError(f"BlockBuilder Version({version}) not supported.")

    @classmethod
    def from_new(cls, block: 'Block', tx_versioner: 'TransactionVersioner'):
        block_builder = cls.new(block.header.version, tx_versioner)
        block_builder.from_(block)
        return block_builder

    def from_(self, block: 'Block'):
        self.height = block.header.height
        self.prev_hash = block.header.prev_hash

        self.transactions = OrderedDict(block.body.transactions)

        self.block = block
        self.hash = block.header.hash
        self.signature = block.header.signature
        self.peer_id = block.header.peer_id

    @abstractmethod
    def get_vote_result(self, block_info):
        raise NotImplementedError
