from typing import TYPE_CHECKING

from loopchain.rest_server.json_rpc import GenericJsonRpcServerError
from loopchain.blockchain.blocks import BlockBuilder, BlockVerifier as BaseBlockVerifier
from loopchain.blockchain.blocks.v0_1a import BlockHeader
from loopchain.blockchain.exception import ScoreInvokeError, ScoreInvokeResultError

if TYPE_CHECKING:
    from loopchain.blockchain.types import ExternalAddress
    from loopchain.blockchain.blocks import Block
    from loopchain.blockchain.blocks.v0_1a import BlockBody


class BlockVerifier(BaseBlockVerifier):
    version = BlockHeader.version

    def _verify_common(self, block: 'Block', prev_block: 'Block', generator: 'ExternalAddress'=None, **kwargs):
        header: BlockHeader = block.header
        body: BlockBody = block.body

        builder = BlockBuilder.new(self.version, self._tx_versioner)
        builder.height = header.height
        builder.prev_hash = header.prev_hash
        builder.fixed_timestamp = header.timestamp

        for tx in body.transactions.values():
            builder.transactions[tx.hash] = tx

        invoke_result = None
        if self.invoke_func:
            self.verify_invoke(builder, block, prev_block)

        builder.build_merkle_tree_root_hash()
        if header.merkle_tree_root_hash != builder.merkle_tree_root_hash:
            exception = RuntimeError(f"Block({header.height}, {header.hash.hex()}, "
                                     f"MerkleTreeRootHash({header.merkle_tree_root_hash.hex()}), "
                                     f"Expected({builder.merkle_tree_root_hash.hex()}).")
            self._handle_exception(exception)

        builder.build_hash()
        if header.hash != builder.hash:
            exception = RuntimeError(f"Block({header.height}, {header.hash.hex()}, "
                                     f"Hash({header.hash.hex()}, "
                                     f"Expected({builder.hash.hex()}).")
            self._handle_exception(exception)

        if generator:
            self.verify_generator(block, generator)

        return invoke_result

    def verify_invoke(self, builder: 'BlockBuilder', block: 'Block', prev_block: 'Block'):
        header: BlockHeader = block.header
        try:
            new_block, invoke_result = self.invoke_func(block, prev_block)
        except GenericJsonRpcServerError as e:
            if hasattr(e, 'message') and 'Failed to invoke a block' in e.message:
                e = ScoreInvokeError(f"{e.message} with block({header.hash.hex()})")
            self._handle_exception(e)
        except Exception as e:
            self._handle_exception(e)
        else:
            if not header.commit_state and len(block.body.transactions) == 0:
                # vote block
                pass
            elif header.commit_state != new_block.header.commit_state:
                exception = ScoreInvokeResultError(f"Block({header.height}, {header.hash.hex()}, "
                                                   f"CommitState({header.commit_state}), "
                                                   f"Expected({new_block.header.commit_state}).")
                self._handle_exception(exception)

    def verify_prev_block(self, block: 'Block', prev_block: 'Block'):
        super().verify_prev_block(block, prev_block)
        prev_block_header: BlockHeader = prev_block.header
        block_header: BlockHeader = block.header

        if not block_header.complained and prev_block_header.next_leader and \
                prev_block_header.next_leader != block_header.peer_id:
            exception = RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()}, "
                                     f"Leader({block_header.peer_id.hex_xx()}), "
                                     f"Expected({prev_block_header.next_leader.hex_xx()}).")
            self._handle_exception(exception)

    def verify_generator(self, block: 'Block', generator: 'ExternalAddress'):
        block_header: BlockHeader = block.header
        if not block_header.complained and block.header.peer_id != generator:
            exception = RuntimeError(f"Block({block.header.height}, {block.header.hash.hex()}, "
                                     f"Generator({block.header.peer_id.hex_xx()}), "
                                     f"Expected({generator.hex_xx()}).")
            self._handle_exception(exception)

    def _handle_exception(self, exception: Exception):
        if self._raise_exceptions:
            raise exception
        else:
            self.exceptions.append(exception)
