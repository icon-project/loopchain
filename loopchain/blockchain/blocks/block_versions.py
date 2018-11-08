import bisect


class BlockVersions:
    def __init__(self):
        self._version_heights = []
        self._version_names = []

    def add_version(self, height: int, version: str):
        index = bisect.bisect(self._version_heights, height)

        check_index = index - 1
        if check_index >= 0 and self._version_heights[check_index] == height:
            raise RuntimeError(f"Duplicated block height version setting. height: {height}, version: {version}")

        self._version_heights.insert(index, height)
        self._version_names.insert(index, version)

    def get_version(self, height: int):
        index = bisect.bisect(self._version_heights, height)
        if index == 0:
            raise RuntimeError(f"There is no block version for the height. height: {height}")

        return self._version_names[index - 1]
