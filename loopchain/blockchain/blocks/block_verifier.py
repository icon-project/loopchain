# Copyright 2018 ICON Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import hashlib
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Callable

from secp256k1 import PrivateKey, PublicKey

from .. import ExternalAddress, BlockVersionNotMatch

if TYPE_CHECKING:
    from . import Block
    from .. import TransactionVersioner


class BlockVerifier(ABC):
    version = None
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

    def verify_version(self, block: 'Block'):
        if block.header.version != self.version:
            raise BlockVersionNotMatch(block.header.version, self.version,
                                       f"The block version is incorrect. Block({block.header})")

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
