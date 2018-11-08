from . import genesis, v2, v3


class TransactionVersions:
    def get_version(self, tx_data: dict):
        if 'signature' not in tx_data:
            return genesis.version

        version = tx_data.get('version')
        if version:
            return version

        return "0x2"

    def get_hash_generator_version(self, version: str):
        if version == "genesis":
            return 0

        return 1
