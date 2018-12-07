from . import genesis, v2, v3


class TransactionVersioner:
    def __init__(self):
        self.hash_generator_versions = dict(default_hash_generator_versions)

    def get_version(self, tx_data: dict):
        if 'signature' not in tx_data:
            return genesis.version

        version = tx_data.get('version')
        if version:
            return version

        return v2.version

    def get_hash_generator_version(self, version: str):
        return self.hash_generator_versions[version]


default_hash_generator_versions = {
    genesis.version: 1,
    v2.version: 1,
    v3.version: 1,
}
