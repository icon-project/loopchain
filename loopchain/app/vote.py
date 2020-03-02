from hashlib import sha3_256
from typing import Type, TypeVar
from lft.consensus.messages.vote import Vote, VoteVerifier, VoteFactory

__all__ = ("DefaultVote", "DefaultVoteFactory", "DefaultVoteVerifier")

T = TypeVar("T")


class DefaultVote(Vote):
    NoneVote = bytes(16)
    LazyVote = bytes([255] * 16)

    def __init__(self, id_: bytes, data_id: bytes, commit_id: bytes, voter_id: bytes, epoch_num: int, round_num: int):
        self._id = id_
        self._data_id = data_id
        self._commit_id = commit_id
        self._voter_id = voter_id
        self._epoch_num = epoch_num
        self._round_num = round_num

    @property
    def id(self) -> bytes:
        return self._id

    @property
    def data_id(self) -> bytes:
        return self._data_id

    @property
    def commit_id(self) -> bytes:
        return self._commit_id

    @property
    def epoch_num(self) -> int:
        return self._epoch_num

    @property
    def voter_id(self) -> bytes:
        return self._voter_id

    @property
    def round_num(self) -> int:
        return self._round_num

    def is_none(self) -> bool:
        return self._data_id == self.NoneVote

    def is_lazy(self) -> bool:
        return self._data_id == self.LazyVote

    def _serialize(self) -> dict:
        return {
            "id": self.id,
            "data_id": self.data_id,
            "commit_id": self.commit_id,
            "voter_id": self.voter_id,
            "epoch": self.epoch_num,
            "round": self.round_num,
        }

    @classmethod
    def _deserialize(cls: Type[T], **kwargs) -> T:
        return DefaultVote(
            id_=kwargs["id"],
            data_id=kwargs["data_id"],
            commit_id=kwargs["commit_id"],
            voter_id=kwargs["voter_id"],
            epoch_num=kwargs["epoch"],
            round_num=kwargs["round"]
        )

    def __repr__(self):
        return f"{self.__class__.__qualname__}({self._serialize()})"

    def __str__(self):
        serialized = {k: "0x" + v.hex() if isinstance(v, bytes) else v for k, v in self._serialize().items()}
        return f"{self.__class__.__qualname__}({serialized})"


class DefaultVoteVerifier(VoteVerifier):
    async def verify(self, vote: 'DefaultVote'):
        pass


class DefaultVoteFactory(VoteFactory):
    def __init__(self, node_id: bytes):
        self._node_id = node_id

    def _create_id(self,
                   data_id: bytes, commit_id: bytes, voter_id: bytes, epoch_num: int, round_num: int) -> bytes:
        source = data_id + commit_id + voter_id + epoch_num.to_bytes(64, 'big') + round_num.to_bytes(64, 'big')
        return sha3_256(source).digest()[:16]

    async def create_vote(self,
                          data_id: bytes, commit_id: bytes, epoch_num: int, round_num: int) -> DefaultVote:
        vote_id = self._create_id(data_id, commit_id, self._node_id, epoch_num, round_num)
        return DefaultVote(vote_id, data_id, commit_id, self._node_id, epoch_num, round_num)

    def create_none_vote(self, epoch_num: int, round_num: int) -> DefaultVote:
        vote_id = self._create_id(DefaultVote.NoneVote, DefaultVote.NoneVote, self._node_id, epoch_num, round_num)
        return DefaultVote(vote_id, DefaultVote.NoneVote, DefaultVote.NoneVote, self._node_id, epoch_num, round_num)

    def create_lazy_vote(self, voter_id: bytes, epoch_num: int, round_num: int) -> DefaultVote:
        vote_id = self._create_id(voter_id, voter_id, voter_id, epoch_num, round_num)
        return DefaultVote(vote_id, DefaultVote.LazyVote, DefaultVote.LazyVote, voter_id, epoch_num, round_num)

    async def create_vote_verifier(self) -> DefaultVoteVerifier:
        return DefaultVoteVerifier()
