import base64
from math import ceil
from typing import Union


class FixedBytes(bytes):
    size = None
    prefix = None

    def __new__(cls, *args, **kwargs):
        self = super().__new__(cls, *args, **kwargs)
        if len(self) != cls.size:
            raise RuntimeError

        return self

    def __repr__(self):
        type_name = type(self).__name__
        return type_name + "(" + super().__repr__() + ")"

    @classmethod
    def fromhex(cls, value: Union[str, int]):
        if isinstance(value, str):
            if cls.prefix and cls.prefix == value[:2]:
                value = value[2:]
            result = bytes.fromhex(value)
        else:
            byte_length = ceil(value.bit_length() / 8)
            result = value.to_bytes(byte_length, 'big')
        return cls(result)


class Hash32(FixedBytes):
    size = 32
    prefix = "0x"

    def hex_0x(self):
        return self.prefix + self.hex()


class Address(FixedBytes):
    size = 20
    prefix = "hx"

    def hex_hx(self):
        return "hx" + self.hex()


class Signature(FixedBytes):
    size = 65

    def recover_id(self):
        return self[-1]

    def signature(self):
        return self[:-1]

    def to_base64(self):
        return base64.b64encode(self)

    def to_base64str(self):
        return self.to_base64().decode('utf-8')

    @classmethod
    def from_base64(cls, base64_bytes: bytes):
        sign_bytes = base64.b64decode(base64_bytes)
        return Signature(sign_bytes)

    @classmethod
    def from_base64str(cls, base64_str: str):
        base64_bytes = base64_str.encode('utf-8')
        return cls.from_base64(base64_bytes)
