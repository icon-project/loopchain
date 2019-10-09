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
from typing import Union
from dataclasses import dataclass
from loopchain.blockchain.types import Hash32, ExternalAddress, Signature
from loopchain.blockchain.votes import Vote as BaseVote
from loopchain.crypto.signature import Signer


@dataclass(frozen=True)
class BlockVote(BaseVote[bool]):
    block_height: int
    round_: int
    block_hash: Hash32

    def result(self) -> bool:
        return self.block_hash != Hash32.empty()

    # noinspection PyMethodOverriding
    @classmethod
    def new(cls, signer: Signer, timestamp: int,
            block_height: int, round_: int, block_hash: Union[Hash32, None]) -> 'BlockVote':
        return super().new(signer, timestamp, block_height=block_height, round_=round_, block_hash=block_hash)

    # noinspection PyMethodOverriding
    @classmethod
    def empty(cls, rep: ExternalAddress, block_height: int):
        return cls(rep, 0, Signature.empty(), block_height, Hash32.empty())

    @classmethod
    def _deserialize(cls, data: dict):
        data_deserialized = super()._deserialize(data)
        data_deserialized["block_height"] = int(data["blockHeight"], 16)
        data_deserialized["round_"] = data["round_"]
        data_deserialized["block_hash"] = Hash32.fromhex(data["blockHash"])
        return data_deserialized

    # noinspection PyMethodOverriding
    @classmethod
    def to_origin_data(cls, rep: ExternalAddress, timestamp: int, block_height: int, round_: int, block_hash: Hash32):
        origin_data = super().to_origin_data(rep, timestamp)
        origin_data["blockHeight"] = hex(block_height)
        origin_data["round_"] = round_
        origin_data["blockHash"] = block_hash.hex_0x() if block_hash is not None else None
        return origin_data

    # noinspection PyMethodOverriding
    @classmethod
    def to_hash(cls, rep: ExternalAddress, timestamp: int, block_height: int, round_: int, block_hash: Hash32):
        return super().to_hash(rep, timestamp, block_height=block_height, round_=round_, block_hash=block_hash)


@dataclass(frozen=True)
class LeaderVote(BaseVote[ExternalAddress]):
    block_height: int
    round_: int
    old_leader: ExternalAddress
    new_leader: ExternalAddress

    def result(self) -> ExternalAddress:
        return self.new_leader

    # noinspection PyMethodOverriding
    @classmethod
    def new(cls, signer: Signer, timestamp: int, block_height: int, round_: int,
            old_leader: ExternalAddress, new_leader: ExternalAddress) -> 'LeaderVote':
        return super().new(signer, timestamp, block_height=block_height, round_=round_,
                           old_leader=old_leader, new_leader=new_leader)

    # noinspection PyMethodOverriding
    @classmethod
    def empty(cls, rep: ExternalAddress, block_height: int, round_: int, old_leader: ExternalAddress):
        return cls(rep, 0, Signature.empty(), block_height, round_, old_leader, ExternalAddress.empty())

    @classmethod
    def _deserialize(cls, data: dict):
        data_deserialized = super()._deserialize(data)
        data_deserialized["block_height"] = int(data["blockHeight"], 16)
        data_deserialized["round_"] = data["round_"]
        data_deserialized["old_leader"] = ExternalAddress.fromhex_address(data["oldLeader"])
        data_deserialized["new_leader"] = ExternalAddress.fromhex_address(data["newLeader"])
        return data_deserialized

    # noinspection PyMethodOverriding
    @classmethod
    def to_origin_data(cls, rep: ExternalAddress, timestamp: int, block_height: int, round_: int,
                       old_leader: ExternalAddress, new_leader: ExternalAddress):
        origin_data = super().to_origin_data(rep, timestamp)
        origin_data["blockHeight"] = hex(block_height)
        origin_data["round_"] = round_
        origin_data["oldLeader"] = old_leader.hex_hx()
        origin_data["newLeader"] = new_leader.hex_hx()
        return origin_data

    # noinspection PyMethodOverriding
    @classmethod
    def to_hash(cls, rep: ExternalAddress, timestamp: int,
                block_height: int, round_: int, old_leader: ExternalAddress, new_leader: ExternalAddress):
        return super().to_hash(rep, timestamp, block_height=block_height, round_=round_,
                               old_leader=old_leader, new_leader=new_leader)
