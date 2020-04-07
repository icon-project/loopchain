import base64
from abc import ABCMeta, abstractmethod
from enum import Enum
from typing import Union, Type, TypeVar

T = TypeVar('T', bound='Bytes')


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

    @classmethod
    def new(cls: Type[T]) -> T:
        """
        create sized value.
        :return:
        """
        return cls(bytes(cls.size) if cls.size else 0)

    @classmethod
    def empty(cls):
        return cls.new()

    def hex_xx(self):
        if self.prefix:
            return self.prefix + self.hex()
        return self.hex()

    @classmethod
    def fromhex(cls: Type[T], value: str, ignore_prefix=False, allow_malformed=False) -> Union[T, 'MalformedStr']:
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


class VarBytes(Bytes):
    prefix = '0x'

    def hex_0x(self):
        return self.prefix + self.hex()


class Hash32(VarBytes):
    size = 32


class Address(Bytes, metaclass=ABCMeta):
    size = 20

    @abstractmethod
    def extend(self) -> 'AddressEx':
        raise NotImplementedError

    @classmethod
    def fromhex_address(cls,
                        value: str,
                        allow_malformed=False) -> Union['ExternalAddress', 'ContractAddress', 'MalformedStr']:
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

    def extend(self) -> 'ExternalAddressEx':
        return ExternalAddressEx(ExternalAddressEx.prefix_bytes + self)


class ContractAddress(Address):
    prefix = "cx"

    def hex_cx(self):
        return self.prefix + self.hex()

    def extend(self) -> 'ContractAddressEx':
        return ContractAddressEx(ContractAddressEx.prefix_bytes + self)


class AddressEx(Bytes, metaclass=ABCMeta):
    prefix_bytes = b''
    size = 21

    def hex_xx(self):
        return self.prefix + self.hex()[2:]

    @abstractmethod
    def shorten(self) -> 'Address':
        raise NotImplementedError


class ExternalAddressEx(AddressEx):
    prefix_bytes = b'\x00'
    prefix = "hx"

    def hex_hx(self):
        return self.hex_xx()

    def shorten(self) -> 'ExternalAddress':
        return ExternalAddress(self[len(self.prefix_bytes):])


class ContractAddressEx(AddressEx):
    prefix_bytes = b'\x01'
    prefix = "cx"

    def hex_cx(self):
        return self.hex_xx()

    def shorten(self) -> 'ContractAddress':
        return ContractAddress(self[len(self.prefix_bytes):])


class BloomFilter(VarBytes):
    size = 256

    def __or__(self, other):
        result = int.from_bytes(self, 'big') | int.from_bytes(other, 'big')
        return self.__class__(result.to_bytes(self.size, 'big'))


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
