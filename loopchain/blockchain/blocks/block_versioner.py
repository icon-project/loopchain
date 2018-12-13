import json
from collections import namedtuple
from typing import List, Union

BlockVersion = namedtuple("BlockVersion", ("height", "name"))


class BlockVersioner:
    def __init__(self):
        self._versions: List[BlockVersion] = list(default_block_versions)

    def add_version(self, height: int, version: str):
        index = next((i for i, version in enumerate(self._versions) if height <= version.height), None)
        if index is not None:
            self._versions.index(BlockVersion(height, version))
        else:
            self._versions.append(BlockVersion(height, version))

    def get_version(self, height: int):
        version = next((version for version in reversed(self._versions) if height >= version.height), None)
        if version is None:
            raise RuntimeError(f"There is no block version for the height. height: {height}")

        return version.name

    def get_height(self, block_dumped: Union[str, dict]):
        if isinstance(block_dumped, str):
           block_dumped = json.loads(block_dumped)
        return block_dumped["height"]


default_block_versions = [
    BlockVersion(0, "0.1a")
]
