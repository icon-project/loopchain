"""Make and Restore blockchain essential backup store."""
import json
import os
from typing import TYPE_CHECKING

from loopchain import configure as conf
from loopchain import utils
from loopchain.blockchain.blocks import BlockSerializer

if TYPE_CHECKING:
    from loopchain.blockchain.blocks import Block
    from loopchain.blockchain.types import Hash32
    from loopchain.blockchain import BlockChain


class BackupManager:
    @staticmethod
    def write_tx(block: 'Block', backup_store, origin_store):
        for tx in block.body.transactions.values():
            tx_hash = tx.hash.hex()
            tx_hash_value = origin_store.get(tx_hash.encode(encoding=conf.HASH_KEY_ENCODING))

            backup_store.put(
                tx_hash.encode(encoding=conf.HASH_KEY_ENCODING),
                tx_hash_value
            )

    @staticmethod
    def write_preps(roothash: 'Hash32', backup_store, blockchain: 'BlockChain'):
        preps = blockchain.find_preps_by_roothash(roothash)
        if preps:
            blockchain.write_preps(roothash, preps, backup_store)

    async def make_backup(self, blockchain, block_height):
        if type(block_height) == str:
            block_height = int(block_height)

        db_name = f"backup_db_{block_height}"

        db_dirname = f'db_{db_name}'
        store_path = os.path.join(conf.DEFAULT_STORAGE_PATH, db_dirname)

        backup_store = utils.init_default_key_value_store(db_name, db_name)
        origin_store = blockchain.blockchain_store
        backup_block: 'Block' = blockchain.find_block_by_height(block_height)
        self.write_tx(backup_block, backup_store, origin_store)
        self.write_preps(backup_block.header.reps_hash, backup_store, blockchain)
        self.write_preps(backup_block.header.revealed_next_reps_hash, backup_store, blockchain)

        bit_length = block_height.bit_length()
        byte_length = (bit_length + 7) // 8
        block_height_bytes = block_height.to_bytes(byte_length, byteorder='big')

        block_hash_encoded = backup_block.header.hash.hex().encode(encoding='UTF-8')

        block_serializer = BlockSerializer.new(backup_block.header.version, blockchain.tx_versioner)
        block_serialized = json.dumps(block_serializer.serialize(backup_block))

        block_height_encoded = block_height.to_bytes(conf.BLOCK_HEIGHT_BYTES_LEN, byteorder='big')
        block_height_key = origin_store.get(
            blockchain.BLOCK_HEIGHT_KEY +
            block_height_encoded
        )

        block_dump = origin_store.get(block_height_key)
        block_dump = json.loads(block_dump)
        confirm_info = blockchain.find_confirm_info_by_hash(blockchain.block_versioner.get_hash(block_dump))

        tx_count_bytes = origin_store.get(blockchain.TRANSACTION_COUNT_KEY + block_height_encoded)

        backup_store.put(blockchain.SYNCED_BLOCK_HEIGHT, b'')
        backup_store.put(blockchain.LAST_BLOCK_HEIGHT, block_height_bytes)
        backup_store.put(block_hash_encoded, block_serialized.encode("utf-8"))
        backup_store.put(blockchain.BLOCK_HEIGHT_KEY + block_height_encoded, block_hash_encoded)
        backup_store.put(blockchain.TRANSACTION_COUNT_KEY + block_height_encoded, tx_count_bytes)
        backup_store.put(blockchain.CONFIRM_INFO_KEY + block_hash_encoded, confirm_info)
        backup_store.put(blockchain.NID_KEY, blockchain.find_nid().encode(encoding=conf.HASH_KEY_ENCODING))

        return store_path
