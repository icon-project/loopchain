from hashlib import sha3_256
from typing import Sequence, Type, TypeVar
from lft.app.vote import DefaultVote
from lft.consensus.messages.data import Data, DataVerifier, DataFactory

__all__ = ("DefaultData", "DefaultDataFactory", "DefaultDataVerifier")

T = TypeVar("T")


class DefaultData(Data):
    NoneData = bytes(16)
    LazyData = bytes([255] * 16)

    def __init__(self,
                 id_: bytes,
                 prev_id: bytes,
                 proposer_id: bytes,
                 number: int,
                 epoch_num: int,
                 round_num: int,
                 prev_votes: Sequence['DefaultVote'] = ()):
        self._id = id_
        self._prev_id = prev_id
        self._proposer_id = proposer_id
        self._number = number
        self._epoch_num = epoch_num
        self._round_num = round_num
        self._prev_votes: Sequence['DefaultVote'] = prev_votes

    @property
    def id(self) -> bytes:
        return self._id

    @property
    def prev_id(self) -> bytes:
        return self._prev_id

    @property
    def proposer_id(self) -> bytes:
        return self._proposer_id

    @property
    def epoch_num(self) -> int:
        return self._epoch_num

    @property
    def number(self) -> int:
        return self._number

    @property
    def round_num(self) -> int:
        return self._round_num

    @property
    def prev_votes(self) -> Sequence['DefaultVote']:
        return self._prev_votes

    def is_none(self) -> bool:
        return self._id == self.NoneData

    def is_lazy(self) -> bool:
        return self._id == self.LazyData

    def _serialize(self) -> dict:
        return {
            "id": self.id,
            "prev_id": self.prev_id,
            "proposer_id": self.proposer_id,
            "number": self.number,
            "epoch": self.epoch_num,
            "round": self.round_num,
            "prev_votes": tuple(self.prev_votes)
        }

    @classmethod
    def _deserialize(cls: Type[T], **kwargs) -> T:
        return DefaultData(
            id_=kwargs["id"],
            prev_id=kwargs["prev_id"],
            proposer_id=kwargs["proposer_id"],
            number=kwargs["number"],
            epoch_num=kwargs["epoch"],
            round_num=kwargs["round"],
            prev_votes=tuple(kwargs["prev_votes"])
        )

    def __repr__(self):
        return f"{self.__class__.__qualname__}({self._serialize()})"

    def __str__(self):
        serialized = {k: "0x" + v.hex() if isinstance(v, bytes) else v for k, v in self._serialize().items()}
        return f"{self.__class__.__qualname__}({serialized})"


class DefaultDataVerifier(DataVerifier):
    async def verify(self, data: 'DefaultData'):
        pass


class DefaultDataFactory(DataFactory):
    def __init__(self, node_id: bytes):
        self._node_id = node_id

    def _create_id(self,
                   prev_id: bytes,
                   propose_id: bytes,
                   data_number: int,
                   epoch_num: int,
                   round_num: int,
                   prev_votes: Sequence['DefaultVote']) -> bytes:
        source = (prev_id + propose_id + data_number.to_bytes(64, 'big') +
                  epoch_num.to_bytes(64, 'big') + round_num.to_bytes(64, 'big') +
                  b"".join(prev_vote.id if prev_vote else bytes(16) for prev_vote in prev_votes))
        return sha3_256(source).digest()[:16]

    async def create_data(self,
                          data_number: int,
                          prev_id: bytes,
                          epoch_num: int,
                          round_num: int,
                          prev_votes: Sequence['DefaultVote']) -> DefaultData:
        data_id = self._create_id(prev_id, self._node_id, data_number, epoch_num, round_num, prev_votes)
        return DefaultData(data_id, prev_id, self._node_id, data_number, epoch_num, round_num, prev_votes=prev_votes)

    def create_none_data(self,
                         epoch_num: int,
                         round_num: int,
                         proposer_id: bytes) -> 'Data':
        return DefaultData(DefaultData.NoneData, DefaultData.NoneData, proposer_id, -1, epoch_num, round_num)

    def create_lazy_data(self,
                         epoch_num: int,
                         round_num: int,
                         proposer_id: bytes) -> DefaultData:
        return DefaultData(DefaultData.LazyData, DefaultData.LazyData, proposer_id, -1, epoch_num, round_num)

    async def create_data_verifier(self) -> DefaultDataVerifier:
        return DefaultDataVerifier()

