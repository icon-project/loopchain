from collections import OrderedDict
from dataclasses import dataclass
from typing import Sequence

from lft.consensus.messages.data import Data
from lft.consensus.messages.vote import Vote

from loopchain.blockchain.blocks import (BlockHeader as BaseBlockHeader,
                                         BlockBody as BaseBlockBody)
from loopchain.blockchain.transactions import TransactionVersioner
from loopchain.blockchain.transactions.v3 import TransactionSerializer
from loopchain.blockchain.types import Hash32, BloomFilter, ExternalAddress
from loopchain.blockchain.types import Signature
from loopchain.blockchain.votes.v1_0.vote import BlockVote
from loopchain.crypto.hashing import build_hash_generator


@dataclass(frozen=True)
class BlockHeader(BaseBlockHeader):
    version = "1.0"

    epoch: int
    round: int

    validators_hash: Hash32
    next_validators_hash: Hash32
    prev_votes_hash: Hash32

    transactions_hash: Hash32

    prev_state_hash: Hash32
    prev_receipts_hash: Hash32
    prev_logs_bloom: BloomFilter


@dataclass(frozen=True)
class BlockBody(BaseBlockBody):
    prev_votes: Sequence['BlockVote']


class Block(Data):
    NoneData = bytes(16)
    LazyData = bytes([255] * 16)

    def __init__(self, header, body):
        self._header: BlockHeader = header
        self._body: BlockBody = body

    def __repr__(self):
        return f"{self.__class__.__name__}" \
               f"(header={self._header}, " \
               f"body={self._body})"

    @property
    def header(self) -> BlockHeader:
        return self._header

    @property
    def body(self) -> BlockBody:
        return self._body

    @property
    def number(self) -> int:
        return self._header.height

    @property
    def prev_id(self) -> bytes:
        return self._header.prev_hash

    @property
    def proposer_id(self) -> bytes:
        return self._header.peer_id

    @property
    def prev_votes(self) -> Sequence['Vote']:
        return self._body.prev_votes

    @property
    def id(self) -> bytes:
        return self._header.hash

    @property
    def epoch_num(self) -> int:
        return self._header.epoch

    @property
    def round_num(self) -> int:
        return self._header.round

    def is_none(self) -> bool:
        return self.id == self.NoneData

    def is_lazy(self) -> bool:
        return self.id == self.LazyData

    def _serialize(self) -> dict:
        header: BlockHeader = self.header

        transactions = []
        for tx in self.body.transactions.values():
            ts = TransactionSerializer.new(tx.version, tx.type(), TransactionVersioner())
            tx_serialized = ts.to_full_data(tx)
            transactions.append(tx_serialized)

        prev_votes = []
        for prev_vote in self.body.prev_votes:
            prev_vote_serialized = prev_vote.serialize()["!data"]
            prev_votes.append(prev_vote_serialized)

        return {
            "version": header.version,
            "hash": header.hash.hex_0x(),
            "prevHash": header.prev_hash.hex_0x(),
            "prevVotesHash": header.prev_votes_hash.hex_0x(),
            "transactionsHash": header.transactions_hash.hex_0x(),
            "prevStateHash": header.prev_state_hash.hex_0x(),
            "prevReceiptsHash": header.prev_receipts_hash.hex_0x(),
            "validatorsHash": header.validators_hash.hex_0x(),
            "nextValidatorsHash": header.next_validators_hash.hex_0x(),
            "prevLogsBloom": header.prev_logs_bloom.hex_0x(),
            "timestamp": hex(header.timestamp),
            "height": hex(header.height),
            "leader": header.peer_id.hex_hx(),
            "epoch": self.epoch_num,
            "round": self.round_num,
            "signature": header.signature.to_base64str(),
            "transactions": transactions,
            "prevVotes": prev_votes
        }

    @classmethod
    def _deserialize(cls, **data):
        epoch_num = data["epoch"] if isinstance(data.get("epoch"), int) else int(data["epoch"], 16)
        round_num = data["round"] if isinstance(data.get("round"), int) else int(data["round"], 16)

        header = BlockHeader(
            hash=Hash32.fromhex(data["hash"]),
            prev_hash=Hash32.fromhex(data["prevHash"]),
            height=int(data["height"], 16),
            timestamp=int(data["timestamp"], 16),
            peer_id=ExternalAddress.fromhex(data["leader"]),
            signature=Signature.from_base64str(data["signature"]),
            epoch=epoch_num,
            round=round_num,
            validators_hash=Hash32.fromhex(data["validatorsHash"]),
            next_validators_hash=Hash32.fromhex(data["nextValidatorsHash"]),
            prev_votes_hash=Hash32.fromhex(data["prevVotesHash"]),
            transactions_hash=Hash32.fromhex(data["transactionsHash"]),
            prev_state_hash=Hash32.fromhex(data["prevStateHash"]),
            prev_receipts_hash=Hash32.fromhex(data["prevReceiptsHash"]),
            prev_logs_bloom=BloomFilter.fromhex(data["prevLogsBloom"])
        )

        prev_votes = []
        for prev_vote in data["prevVotes"]:
            prev_vote_loaded = BlockVote._deserialize(**prev_vote)
            prev_votes.append(prev_vote_loaded)

        tx_versioner = TransactionVersioner()
        transactions = OrderedDict()
        for tx_data in data['transactions']:
            tx_version, tx_type = tx_versioner.get_version(tx_data)
            ts = TransactionSerializer.new(tx_version, tx_type, tx_versioner)
            tx = ts.from_(tx_data)
            transactions[tx.hash] = tx

        body = BlockBody(
            prev_votes=prev_votes,
            transactions=transactions
        )
        return cls(header=header, body=body)


receipts_hash_generator = build_hash_generator(1, "icx_receipt")
