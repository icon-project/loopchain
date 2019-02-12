import base64
from abc import ABCMeta
from enum import Enum
from typing import Union


class Bytes(bytes):
    size = None
    prefix = None

    def __new__(cls, *args, **kwargs):
        self = super().__new__(cls, *args, **kwargs)
        if cls.size is not None and cls.size != len(self):
            raise RuntimeError

        return self

    def __repr__(self):
        type_name = type(self).__qualname__
        return type_name + "(" + super().__repr__() + ")"

    def __str__(self):
        type_name = type(self).__qualname__
        return type_name + "(" + self.hex_xx() + ")"

    def hex_xx(self):
        if self.prefix:
            return self.prefix + self.hex()
        return self.hex()

    @classmethod
    def fromhex(cls, value: str, ignore_prefix=False, allow_malformed=False):
        if isinstance(cls, Address):
            raise TypeError("Address.fromhex() cannot be used. Because Address is ABC.")

        try:
            if cls.prefix and not ignore_prefix:
                prefix, contents = value[:len(cls.prefix)], value[len(cls.prefix):]
                if prefix != cls.prefix:
                    raise ValueError(f"Invalid prefix. {cls.__qualname__}, {value}")
            else:
                contents = value

            if len(contents) != cls.size * 2:
                raise ValueError(f"Invalid size. {cls.__qualname__}, {value}")
            if contents.lower() != contents:
                raise ValueError(f"All elements of value must be lower cases. {cls.__qualname__}, {value}")

            return cls(bytes.fromhex(contents))
        except:
            if not allow_malformed:
                raise

        return MalformedStr(cls, value)


class Hash32(Bytes):
    size = 32
    prefix = "0x"

    def hex_0x(self):
        return self.prefix + self.hex()


class Address(Bytes, metaclass=ABCMeta):
    size = 20

    @classmethod
    def fromhex_address(cls, value: int, allow_malformed=False):
        try:
            prefix, contents = value[:2], value[2:]

            if len(contents) != cls.size * 2:
                raise ValueError(f"Invalid size. {cls.__qualname__}, {value}")
            if contents.lower() != contents:
                raise ValueError(f"All elements of value must be lower cases. {cls.__qualname__}, {value}")

            if prefix == ContractAddress.prefix:
                return ContractAddress(bytes.fromhex(contents))

            if prefix == ExternalAddress.prefix:
                return ExternalAddress(bytes.fromhex(contents))

            raise ValueError(f"Invalid prefix. {cls.__qualname__}, {value}")
        except:
            if not allow_malformed:
                raise

        return MalformedStr(cls, value)


class ExternalAddress(Address):
    prefix = "hx"

    def hex_hx(self):
        return self.prefix + self.hex()


class ContractAddress(Address):
    prefix = "cx"

    def hex_cx(self):
        return self.prefix + self.hex()


class Signature(Bytes):
    size = 65

    def recover_id(self):
        return self[-1]

    def signature(self):
        return self[:-1]

    def to_base64(self):
        return base64.b64encode(self)

    def to_base64str(self):
        return self.to_base64().decode('utf-8')

    def __str__(self):
        type_name = type(self).__qualname__
        return type_name + "(" + self.to_base64str() + ")"

    @classmethod
    def from_base64(cls, base64_bytes: bytes):
        sign_bytes = base64.b64decode(base64_bytes)
        return Signature(sign_bytes)

    @classmethod
    def from_base64str(cls, base64_str: str):
        base64_bytes = base64_str.encode('utf-8')
        return cls.from_base64(base64_bytes)


class MalformedStr:
    def __init__(self, origin_type, value):
        self.origin_type = origin_type
        self.value = value

    def hex(self):
        return self.value

    def hex_xx(self):
        return self.value

    def hex_hx(self):
        return self.value

    def hex_0x(self):
        return self.value

    def str(self):
        return self.value

    def __eq__(self, other):
        if type(self) is not type(other):
            return False

        return self.origin_type == other.origin_type and self.value == other.value

    def __hash__(self):
        return hash(self.origin_type) ^ hash(self.value)

    def __repr__(self):
        type_name = type(self).__qualname__
        origin_type_name = self.origin_type.__qualname__
        return type_name + f"({origin_type_name}, {repr(self.value)})"

    def __str__(self):
        type_name = type(self).__qualname__
        origin_type_name = self.origin_type.__qualname__
        return type_name + f"({origin_type_name}, {self.value})"


def int_fromhex(value: str):
    if not isinstance(value, str):
        raise ValueError(f"This is not string. {value}")

    if value == value.replace("0x", ""):
        return MalformedStr(int, value)

    if value != value.lower():
        return MalformedStr(int, value)

    try:
        return int(value, 16)
    except ValueError:
        return MalformedStr(int, value)


def int_tohex(value: Union[int, MalformedStr]):
    if isinstance(value, int):
        return hex(value)

    return value.hex_xx()


def int_fromstr(value: Union[str, int]):
    try:
        return int(value)
    except ValueError:
        return MalformedStr(int, value)


def int_tostr(value: Union[int, MalformedStr]):
    if isinstance(value, int):
        return str(value)

    return value.str()


class TransactionStatusInQueue(Enum):
    normal = 1
    fail_validation = 2
    fail_invoke = 3
    added_to_block = 4
    precommited_to_block = 5
