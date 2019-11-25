from pathlib import Path
from typing import Dict, Union, List

from iconsdk.exception import DataTypeException, KeyStoreException
from iconsdk.wallet.wallet import KeyWallet


class Key:
    def __init__(self, path, password):
        self._path: Path = path
        self._password = password
        self._wallet = self._init_wallet()

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
        try:
            self._wallet.store(file_path=self._path, password=self._password)
        except KeyStoreException as e:
            raise FileExistsError from e

    def _init_wallet(self):
        if self._path.exists():
            wallet = self._init_with_exist_key()
        else:
            wallet = KeyWallet.create()

        return wallet

    def _init_with_exist_key(self):
        try:
            wallet = KeyWallet.load(str(self._path), self._password)
        except DataTypeException:
            wallet = KeyWallet.create()

        return wallet


Config = Dict[str, Union[int, str, dict]]
Keys = List[Key]
