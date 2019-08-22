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

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Callable

from loopchain import configure as conf
from loopchain import utils
from loopchain.blockchain.exception import BlockVersionNotMatch
from loopchain.blockchain.transactions import TransactionVerifier
from loopchain.blockchain.types import ExternalAddress
from loopchain.crypto.signature import SignVerifier

if TYPE_CHECKING:
    from loopchain.blockchain.blocks import Block, BlockHeader
    from loopchain.blockchain.transactions import TransactionVersioner


class BlockVerifier(ABC):
    version = None

    def __init__(self, tx_versioner: 'TransactionVersioner', raise_exceptions=True):
        self._tx_versioner = tx_versioner
        self._raise_exceptions = raise_exceptions

        self.exceptions = []
        self.invoke_func: Callable[['Block'], ('Block', dict)] = None

    def verify(self, block: 'Block', prev_block: 'Block', blockchain=None, generator: 'ExternalAddress'=None, **kwargs):
        self.verify_transactions(block, blockchain)
        return self.verify_common(block, prev_block, generator, **kwargs)

    def verify_loosely(self, block: 'Block', prev_block: 'Block',
                       blockchain=None, generator: 'ExternalAddress'=None, **kwargs):
        self.verify_transactions_loosely(block, blockchain)
        return self.verify_common(block, prev_block, generator, **kwargs)

    def verify_common(self, block: 'Block', prev_block: 'Block', generator: 'ExternalAddress'=None, **kwargs):
        header: BlockHeader = block.header

        if header.timestamp is None:
            exception = RuntimeError(f"Block({header.height}, {header.hash.hex()} does not have timestamp.")
            self._handle_exception(exception)

        if header.height > 0 and header.prev_hash is None:
            exception = RuntimeError(f"Block({header.height}, {header.hash.hex()} does not have prev_hash.")
            self._handle_exception(exception)

        self.verify_version(block)

        if block.header.signature or block.header.height > 0:
            self.verify_signature(block)

        if prev_block:
            self.verify_prev_block(block, prev_block)

        return self._verify_common(block, prev_block, generator, **kwargs)

    @abstractmethod
    def verify_invoke(self, builder: 'BlockBuilder', block: 'Block', prev_block: 'Block'):
        raise NotImplementedError

    @abstractmethod
    def _verify_common(self, block: 'Block', prev_block: 'Block', generator: 'ExternalAddress'=None, **kwargs):
        raise NotImplementedError

    def verify_transactions(self, block: 'Block', blockchain=None):
        for tx in block.body.transactions.values():
            tv = TransactionVerifier.new(tx.version, tx.type(), self._tx_versioner, self._raise_exceptions)
            tv.verify(tx, blockchain)
            if not self._raise_exceptions:
                self.exceptions.extend(tv.exceptions)

    def verify_transactions_loosely(self, block: 'Block', blockchain=None):
        for tx in block.body.transactions.values():
            tv = TransactionVerifier.new(tx.version, tx.type(), self._tx_versioner, self._raise_exceptions)
            tv.verify_loosely(tx, blockchain)
            if not self._raise_exceptions:
                self.exceptions.extend(tv.exceptions)

    def verify_version(self, block: 'Block'):
        if block.header.version != self.version:
            exception = BlockVersionNotMatch(block.header.version, self.version,
                                             f"The block version is incorrect. Block({block.header})")
            self._handle_exception(exception)

    def verify_prev_block(self, block: 'Block', prev_block: 'Block'):
        if block.header.height != prev_block.header.height + 1:
            exception = RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()}, "
                                     f"Height({block.header.height}), "
                                     f"Expected({prev_block.header.height + 1}).")
            self._handle_exception(exception)

        if block.header.prev_hash != prev_block.header.hash:
            exception = RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()}, "
                                     f"PrevHash({block.header.prev_hash.hex()}), "
                                     f"Expected({prev_block.header.hash.hex()}).")
            self._handle_exception(exception)

        valid_max_timestamp = utils.get_time_stamp() + conf.TIMESTAMP_BUFFER_IN_VERIFIER
        if prev_block and not (prev_block.header.timestamp < block.header.timestamp < valid_max_timestamp):
            exception = RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()},"
                                     f"timestamp({block.header.timestamp} is invalid. "
                                     f"prev_block timestamp({prev_block.header.timestamp}), "
                                     f"current timestamp({utils.get_now_time_stamp()}")
            self._handle_exception(exception)

    def verify_signature(self, block: 'Block'):
        sign_verifier = SignVerifier.from_address(block.header.peer_id.hex_xx())
        try:
            sign_verifier.verify_hash(block.header.hash, block.header.signature)
        except Exception as e:
            exception = RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()}, "
                                     f"Invalid Signature\n"
                                     f"{e}")
            self._handle_exception(exception)

    def verify_generator(self, block: 'Block', generator: 'ExternalAddress'):
        if block.header.peer_id != generator:
            exception = RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()}, "
                                     f"Generator({block.header.peer_id.hex_xx()}), "
                                     f"Expected({generator.hex_xx()}).")
            self._handle_exception(exception)

    def _handle_exception(self, exception: Exception):
        if self._raise_exceptions:
            raise exception
        else:
            self.exceptions.append(exception)

    @classmethod
    def new(cls, version: str, tx_versioner: 'TransactionVersioner', raise_exceptions=True) -> 'BlockVerifier':
        from . import v0_3
        if version == v0_3.version:
            return v0_3.BlockVerifier(tx_versioner, raise_exceptions)

        from . import v0_1a
        if version == v0_1a.version:
            return v0_1a.BlockVerifier(tx_versioner, raise_exceptions)

        raise NotImplementedError(f"BlockBuilder Version({version}) not supported.")
