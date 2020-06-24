"""Make and Restore blockchain essential backup store."""
import json
import os

from loopchain import utils
from loopchain import configure as conf

from loopchain.blockchain.blocks import BlockSerializer

class BackupManager:
    def __init__(self):
        self._backup_store = None

    async def make_backup(self, blockchain, block_height):
        if type(block_height) == str:
            block_height = int(block_height)

        __db_name = f"backup_db_{block_height}"

        db_dirname = f'db_{__db_name}'
        store_path = os.path.join(conf.DEFAULT_STORAGE_PATH, db_dirname)

        self._blackup_store = utils.init_default_key_value_store(__db_name, __db_name)

        __block_info = blockchain.find_block_by_height(block_height)

        for tx in __block_info.body.transactions.values():
            tx_hash = tx.hash.hex()
            tx_hash_value = blockchain.blockchain_store.get(tx_hash.encode(encoding=conf.HASH_KEY_ENCODING))

            self._blackup_store.put(
                tx_hash.encode(encoding=conf.HASH_KEY_ENCODING),
                tx_hash_value
            )

        bit_length = block_height.bit_length()
        byte_length = (bit_length + 7) // 8
        block_height_bytes = block_height.to_bytes(byte_length, byteorder='big')

        block_hash_encoded = __block_info.header.hash.hex().encode(encoding='UTF-8')

        block_serializer = BlockSerializer.new(__block_info.header.version, blockchain.tx_versioner)
        block_serialized = json.dumps(block_serializer.serialize(__block_info))

        block_height_encoded = block_height.to_bytes(conf.BLOCK_HEIGHT_BYTES_LEN, byteorder='big')        
        block_height_key = blockchain.blockchain_store.get(
            blockchain.BLOCK_HEIGHT_KEY +
            block_height_encoded
        )

        blockchain.blockchain_store.get(block_height_key)
        block_dump = blockchain.blockchain_store.get(block_height_key)
        block_dump = json.loads(block_dump)
        confirm_info = blockchain.find_confirm_info_by_hash(blockchain.block_versioner.get_hash(block_dump))
        
        tx_count_bytes = blockchain.blockchain_store.get(blockchain.TRANSACTION_COUNT_KEY + block_height_encoded)
        
        self._blackup_store.put(blockchain.LAST_BLOCK_HEIGHT, block_height_bytes)
        self._blackup_store.put(block_hash_encoded, block_serialized.encode("utf-8"))
        self._blackup_store.put(blockchain.BLOCK_HEIGHT_KEY + block_height_encoded, block_hash_encoded)
        self._blackup_store.put(blockchain.TRANSACTION_COUNT_KEY + block_height_encoded, tx_count_bytes)
        self._blackup_store.put(blockchain.CONFIRM_INFO_KEY + block_hash_encoded, confirm_info)
        self._blackup_store.put(blockchain.NID_KEY, blockchain.find_nid().encode(encoding=conf.HASH_KEY_ENCODING))
        
        return store_path

    def restore_backup(self):
        pass
