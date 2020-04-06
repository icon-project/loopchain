from lft.consensus.messages.vote import Vote

from loopchain.blockchain.types import ExternalAddress, Signature, Hash32
from loopchain.crypto.hashing import build_hash_generator


class BlockVote(Vote):
    NoneVote = Hash32.empty()
    LazyVote = Hash32(bytes([255] * 32))

    def __init__(self, data_id: Hash32, commit_id: Hash32, voter_id: ExternalAddress, epoch_num: int, round_num: int,
                 state_hash: Hash32, receipt_hash: Hash32, timestamp: int, signature: Signature):
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
        self._epoch_num: int = epoch_num
        self._round_num: int = round_num

        # Not in Interface
        self._state_hash: Hash32 = state_hash
        self._receipt_hash: Hash32 = receipt_hash
        self._timestamp: int = timestamp
        self._signature: Signature = signature

        # Created
        self._hash: Hash32 = None

    @property
    def version(self):
        return "1.0"

    @property
    def id(self) -> Hash32:
        return self.hash

    @property
    def hash(self) -> Hash32:
        if self._hash:
            return self._hash
        else:
            origin_data = self._serialize()
            hash_generator = build_hash_generator(1, "icx_vote")
            self._hash = Hash32(hash_generator.generate_hash(origin_data))

            return self._hash

    @property
    def data_id(self) -> Hash32:
        return self._data_id

    @property
    def commit_id(self) -> Hash32:
        return self._commit_id

    @property
    def voter_id(self) -> ExternalAddress:
        return self._voter_id

    @property
    def epoch_num(self) -> int:
        return self._epoch_num

    @property
    def state_hash(self) -> Hash32:
        return self._state_hash

    @property
    def receipt_hash(self) -> Hash32:
        return self._receipt_hash

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
            "blockHash": self._data_id.hex_0x(),
            "commitHash": self._commit_id.hex_0x(),
            "stateHash": self._state_hash.hex_0x(),
            "receiptHash": self._receipt_hash.hex_0x(),
            "epoch": hex(self._epoch_num),
            "round": hex(self._round_num)
        }

    @classmethod
    def _deserialize(cls, **data) -> Vote:
        return cls(
            state_hash=Hash32.fromhex(data["stateHash"]),
            receipt_hash=Hash32.fromhex(data["receiptHash"]),
            data_id=Hash32.fromhex(data["blockHash"]),
            commit_id=Hash32.fromhex(data["commitHash"]),
            voter_id=ExternalAddress.fromhex_address(data["validator"]),
            timestamp=int(data["timestamp"], 16),
            epoch_num=int(data["epoch"], 16),
            round_num=int(data["round"], 16),
            signature=Signature.from_base64str(data["signature"])
        )

    def is_none(self) -> bool:
        """Check that the vote is against a block of `data_id`."""
        return self.data_id == self.NoneVote

    def is_lazy(self) -> bool:
        """Check that the vote is created by timeout."""
        return self.data_id == self.LazyVote
