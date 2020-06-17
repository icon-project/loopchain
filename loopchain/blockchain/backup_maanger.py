"""Make and Restore blockchain essential backup store."""


class BackupManager:
    def __init__(self):
        self._backup_store = None

    async def make_backup(self, blockchain, block_height):
        return "43"

    def restore_backup(self):
        pass
