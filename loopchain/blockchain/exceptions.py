class BlockVersionNotSupportedError(Exception):
    def __init__(self, version: str, msg: str):
        super().__init__(msg)
        self.version = version
        self.msg = msg

    def __str__(self):
        results = []
        if self.msg:
            results.append(self.msg)
        results.append(f"version: {self.version}")
        return ' '.join(results)


class BlockVersionNotMatch(Exception):
    def __init__(self, block_version: str, target_version: str, msg: str):
        super().__init__(msg)
        self.block_version = block_version
        self.target_version = target_version
        self.msg = msg

    def __str__(self):
        results = []
        if self.msg:
            results.append(self.msg)
        results.append(f"block version: {self.block_version}")
        results.append(f"target version: {self.target_version}")
        return ' '.join(results)
