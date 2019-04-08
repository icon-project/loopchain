from loopchain.blockchain.blocks import v0_1a, Block
from loopchain.blockchain.blocks.v0_2 import BlockHeader
from loopchain.blockchain.transactions import v3_issue, TransactionVerifier


class BlockVerifier(v0_1a.BlockVerifier):
    version = BlockHeader.version

    def verify_transactions(self, block: 'Block', blockchain=None):
        txs_iter = iter(block.body.transactions.values())

        if block.header.height > 0:
            issue_tx = next(txs_iter)
            hash_generator_version = self._tx_versioner.get_hash_generator_version(issue_tx.version)
            issue_tx_verifier = v3_issue.TransactionVerifier(hash_generator_version)
            issue_tx_verifier.verify(issue_tx, blockchain)

        for tx in txs_iter:
            tv = TransactionVerifier.new(tx.version, self._tx_versioner)
            tv.verify(tx, blockchain)

    def verify_transactions_loosely(self, block: 'Block', blockchain=None):
        txs_iter = iter(block.body.transactions.values())

        if block.header.height > 0:
            issue_tx = next(txs_iter)
            hash_generator_version = self._tx_versioner.get_hash_generator_version(issue_tx.version)
            issue_tx_verifier = v3_issue.TransactionVerifier(hash_generator_version)
            issue_tx_verifier.verify_loosely(issue_tx, blockchain)

        for tx in txs_iter:
            tv = TransactionVerifier.new(tx.version, self._tx_versioner)
            tv.verify_loosely(tx, blockchain)
