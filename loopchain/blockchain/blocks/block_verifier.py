import hashlib
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Callable
from secp256k1 import PrivateKey, PublicKey
from .. import ExternalAddress

if TYPE_CHECKING:
    from . import Block
    from .. import TransactionVersioner


class BlockVerifier(ABC):
    _ecdsa = PrivateKey()

    def __init__(self, tx_versioner: 'TransactionVersioner'):
        self._tx_versioner = tx_versioner
        self.invoke_func: Callable[['Block'], ('Block', dict)] = None

    @abstractmethod
    def verify(self, block: 'Block', prev_block: 'Block', blockchain=None, generator: 'ExternalAddress'=None):
        raise NotImplementedError

    @abstractmethod
    def verify_loosely(self, block: 'Block', prev_block: 'Block', blockchain=None, generator: 'ExternalAddress'=None):
        raise NotImplementedError

    def verify_signature(self, block: 'Block'):
        recoverable_sig = self._ecdsa.ecdsa_recoverable_deserialize(
            block.header.signature.signature(),
            block.header.signature.recover_id())
        raw_public_key = self._ecdsa.ecdsa_recover(block.header.hash,
                                                   recover_sig=recoverable_sig,
                                                   raw=True,
                                                   digest=hashlib.sha3_256)

        public_key = PublicKey(raw_public_key, ctx=self._ecdsa.ctx)
        hash_pub = hashlib.sha3_256(public_key.serialize(compressed=False)[1:]).digest()
        expect_address = hash_pub[-20:]
        if expect_address != block.header.peer_id:
            raise RuntimeError(f"block peer id {block.header.peer_id.hex_xx()}, "
                               f"expected {ExternalAddress(expect_address).hex_xx()}")

    @classmethod
    def new(cls, version: str, tx_versioner: 'TransactionVersioner') -> 'BlockVerifier':
        from . import v0_1a, v0_2
        if version == v0_1a.version:
            return v0_1a.BlockVerifier(tx_versioner)

        if version == v0_2.version:
            return v0_2.BlockVerifier(tx_versioner)

        raise NotImplementedError(f"BlockBuilder Version({version}) not supported.")

