from pathlib import Path
from typing import Dict, Union, List

from iconsdk.wallet.wallet import KeyWallet


class Key:
    def __init__(self, path, password):
        self._path: Path = path
        self._password = password
        self._wallet: KeyWallet = KeyWallet.create()

    @property
    def path(self) -> Path:
        return self._path

    @property
    def password(self) -> str:
        return self._password

    @property
    def address(self) -> str:
        return self._wallet.address

    def write(self):
        self._wallet.store(file_path=self._path, password=self._password)


Config = Dict[str, Union[int, str, dict]]
Keys = List[Key]
