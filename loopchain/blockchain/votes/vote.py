# Copyright 2018 ICON Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from abc import ABC, abstractmethod
from typing import Generic, TypeVar
from dataclasses import dataclass
from loopchain.blockchain.types import ExternalAddress, Signature, Hash32
from loopchain.crypto.hashing import build_hash_generator
from loopchain.crypto.signature import SignVerifier, Signer

TResult = TypeVar("TResult")
hash_generator = build_hash_generator(1, "icx_vote")


@dataclass(frozen=True)
class Vote(ABC, Generic[TResult]):
    rep: ExternalAddress
    timestamp: int
    signature: Signature

    def origin_args(self):
        args = dict(self.__dict__)
        args.pop("signature", None)
        return args

    def hash(self):
        return self.to_hash(**self.origin_args())

    def serialize(self):
        origin_args = self.origin_args()
        origin_data = self.to_origin_data(**origin_args)
        origin_data["signature"] = self.signature.to_base64str()
        return origin_data

    def verify(self):
        hash_ = self.to_hash(**self.origin_args())
        sign_verifier = SignVerifier.from_address(self.rep.hex_hx())
        try:
            sign_verifier.verify_hash(hash_, self.signature)
        except Exception as e:
            raise RuntimeError(f"Invalid vote signature. {self}"
                               f"{e}")

    @abstractmethod
    def result(self) -> TResult:
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def new(cls, signer: Signer, timestamp: int, **kwargs):
        rep_id: ExternalAddress = ExternalAddress.fromhex(signer.address)

        hash_ = cls.to_hash(rep_id, timestamp, **kwargs)
        signature = Signature(signer.sign_hash(hash_))
        return cls(rep_id, timestamp, signature, **kwargs)

    @abstractmethod
    def empty(self, rep: ExternalAddress, **kwargs):
        raise NotImplementedError

    @classmethod
    def deserialize(cls, data: dict):
        vote_attributes = cls._deserialize(data)
        return cls(**vote_attributes)

    @classmethod
    def _deserialize(cls, data: dict):
        return {
            "rep": ExternalAddress.fromhex_address(data["rep"]),
            "timestamp": int(data["timestamp"], 16),
            "signature": Signature.from_base64str(data["signature"])
        }

    @classmethod
    def to_origin_data(cls, rep: ExternalAddress, timestamp: int, **kwargs):
        return {
            "rep": rep.hex_hx(),
            "timestamp": hex(timestamp)
        }

    @classmethod
    def to_hash(cls, rep: ExternalAddress, timestamp: int, **kwargs):
        origin_data = cls.to_origin_data(rep, timestamp, **kwargs)
        return Hash32(hash_generator.generate_hash(origin_data))
