from typing import TYPE_CHECKING

from lft.consensus.messages.data import DataVerifier

from loopchain.blockchain.transactions import TransactionVersioner

if TYPE_CHECKING:
    from loopchain.blockchain.invoke_result import InvokeResult, InvokePool
    from loopchain.blockchain.blocks.v1_0.block import Block


class BlockVerifier(DataVerifier):
    version = "1.0"

    def __init__(self, tx_versioner: TransactionVersioner, invoke_pool: 'InvokePool'):
        self._invoke_pool: 'InvokePool' = invoke_pool
        self._tx_versioner: TransactionVersioner = tx_versioner

    async def verify(self, prev_data: 'Block', data: 'Block'):
        self._do_invoke(data)

    def _do_invoke(self, block) -> 'InvokeResult':
        invoke_result = self._invoke_pool.invoke(block=block)

        return invoke_result
