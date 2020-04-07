import json
from collections import namedtuple
from typing import List, Union

from loopchain.blockchain.types import Hash32
BlockVersion = namedtuple("BlockVersion", ("height", "name"))


class BlockVersioner:
    def __init__(self):
        self._versions: List[BlockVersion] = default_block_versions

    def add_version(self, height: int, version_name: str):
        if self._versions is default_block_versions:
            self._versions = []

        try:
            next(version for version in self._versions if version.height == height)
        except StopIteration:  # Not duplicated
            pass
        else:
            raise ValueError(f"Duplicated block version. {version_name}, {height}. {self._versions}")

        self._versions.append(BlockVersion(height, version_name))
        self._versions.sort(key=lambda version: version.height)

    def get_version(self, height: int):
        try:
            version = next(version for version in reversed(self._versions) if version.height <= height)
        except StopIteration:
            raise RuntimeError(f"There is no block version for the height. height: {height}")
        else:
            return version.name

    def get_height(self, block_dumped: Union[str, dict]):
        if isinstance(block_dumped, str):
            block_dumped = json.loads(block_dumped)
        height = block_dumped["height"]
        return int(height, 16) if isinstance(height, str) else height

    def get_hash(self, block_dumped: Union[str, dict]):
        if isinstance(block_dumped, str):
            block_dumped = json.loads(block_dumped)

        hash_ = block_dumped.get("block_hash") or block_dumped.get("hash")
        ignore_prefix = block_dumped['version'] == '0.1a'
        return Hash32.fromhex(hash_, ignore_prefix) if isinstance(hash_, str) else hash_


default_block_versions = [
    BlockVersion(0, "0.1a")
]
