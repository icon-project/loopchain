from lft.consensus.messages.vote import Vote

from loopchain.blockchain.types import ExternalAddress, Signature, Hash32
from loopchain.crypto.hashing import build_hash_generator
from loopchain.crypto.signature import SignVerifier


class BlockVote(Vote):
    NoneVote = Hash32.empty()
    LazyVote = Hash32(bytes([255] * 32))

    def __init__(self, data_id: Hash32, commit_id: Hash32, voter_id: ExternalAddress, epoch_num: int, round_num: int,
                 state_hash: Hash32, receipt_hash: Hash32, next_validators_hash: Hash32,
                 timestamp: int, signature: Signature, height: int, _hash=None):
        """Vote.

        :param state_hash:
        :param receipt_hash:
        :param data_id: Block hash to vote
        :param commit_id: Prev block hash of the vote
        :param voter_id: Peer ID of the validator
        :param timestamp:
        :param epoch_num: Epoch Number
        :param round_num: Round Number
        :param signature:
        """

        # Basic
        self._data_id: Hash32 = data_id
        self._commit_id: Hash32 = commit_id
        self._voter_id: ExternalAddress = voter_id
        self._height: int = height
        self._epoch_num: int = epoch_num
        self._round_num: int = round_num

        # Not in Interface
        self._state_hash: Hash32 = state_hash
        self._receipt_hash: Hash32 = receipt_hash
        self._next_validators_hash: Hash32 = next_validators_hash
        self._timestamp: int = timestamp
        self._signature: Signature = signature

        # Optional
        if _hash:
            self._hash = _hash
        else:
            origin_data = self._serialize()
            self._hash = self._to_hash(origin_data)

    def __repr__(self):
        return f"{self.__class__.__name__}" \
               f"(data_id={self._data_id}, " \
               f"commit_id={self._commit_id}, " \
               f"height={self._height}, " \
               f"voter_id={self._voter_id.hex_hx()}, " \
               f"epoch_num={self._epoch_num}, " \
               f"round_num={self._round_num}, " \
               f"state_hash={self._state_hash}, " \
               f"receipt_hash={self._receipt_hash}, "\
               f"next_validators_hash={self._next_validators_hash}, " \
               f"timestamp={self._timestamp}, " \
               f"signature={self._signature}, " \
               f"hash={self._hash})"

    @property
    def version(self):
        return "1.0"

    @property
    def id(self) -> Hash32:
        return self.hash

    @property
    def hash(self) -> Hash32:
        return self._hash

    @property
    def data_id(self) -> Hash32:
        return self._data_id

    @property
    def commit_id(self) -> Hash32:
        return self._commit_id

    @property
    def consensus_id(self) -> Hash32:
        return self._data_id ^ self._state_hash ^ self._receipt_hash ^ self._next_validators_hash

    @property
    def voter_id(self) -> ExternalAddress:
        return self._voter_id

    @property
    def epoch_num(self) -> int:
        return self._epoch_num

    @property
    def block_height(self) -> int:
        return self._height

    @property
    def state_hash(self) -> Hash32:
        return self._state_hash

    @property
    def receipt_hash(self) -> Hash32:
        return self._receipt_hash

    @property
    def next_validators_hash(self) -> Hash32:
        return self._next_validators_hash

    @property
    def timestamp(self) -> int:
        return self._timestamp

    @property
    def signature(self) -> Signature:
        return self._signature

    @property
    def round_num(self) -> int:
        return self._round_num

    def _serialize(self, **kwarg) -> dict:
        """Serialize Vote.

        Note that Vote hash is not included in but is derived from this data.
        """
        return {
            "validator": self._voter_id.hex_hx(),
            "timestamp": hex(self._timestamp),
            "blockHeight": hex(self._height),
            "blockHash": self._data_id.hex_0x(),
            "commitHash": self._commit_id.hex_0x(),
            "stateHash": self._state_hash.hex_0x(),
            "receiptHash": self._receipt_hash.hex_0x(),
            "nextValidatorsHash": self._next_validators_hash.hex_0x(),
            "epoch": hex(self._epoch_num),
            "round": hex(self._round_num),
            "signature": self._signature.to_base64str()
        }

    @classmethod
    def _deserialize(cls, **data) -> Vote:
        return cls(
            state_hash=Hash32.fromhex(data["stateHash"]),
            receipt_hash=Hash32.fromhex(data["receiptHash"]),
            next_validators_hash=Hash32.fromhex(data["nextValidatorsHash"]),
            data_id=Hash32.fromhex(data["blockHash"]),
            commit_id=Hash32.fromhex(data["commitHash"]),
            voter_id=ExternalAddress.fromhex_address(data["validator"]),
            timestamp=int(data["timestamp"], 16),
            epoch_num=int(data["epoch"], 16),
            round_num=int(data["round"], 16),
            signature=Signature.from_base64str(data["signature"]),
            height=int(data["blockHeight"], 16)
        )

    def _to_hash(self, origin_data: dict):
        hash_generator = build_hash_generator(1, "icx_vote")
        return Hash32(hash_generator.generate_hash(origin_data))

    def _to_origin_data(self):
        return {
            "validator": self._voter_id.hex_hx(),
            "timestamp": hex(self._timestamp),
            "blockHeight": hex(self._height),
            "blockHash": Hash32(self._data_id),
            "commitHash": Hash32(self._commit_id),
            "stateHash": self._state_hash,
            "receiptHash": self._receipt_hash,
            "nextValidatorsHash": self._next_validators_hash,
            "epoch": self._epoch_num,
            "round": self._round_num
        }

    def is_none(self) -> bool:
        """Check that the vote is against a block of `data_id`."""
        return self.data_id == self.NoneVote

    def is_lazy(self) -> bool:
        """Check that the vote is created by timeout."""
        return self.data_id == self.LazyVote

    def verify(self):
        origin_data = self._to_origin_data()
        hash_ = self._to_hash(origin_data)
        sign_verifier = SignVerifier.from_address(self.voter_id.hex_hx())
        try:
            sign_verifier.verify_hash(hash_, self._signature)
        except Exception as e:
            raise RuntimeError(f"Invalid vote signature. {self}\n"
                               f"{e}")
