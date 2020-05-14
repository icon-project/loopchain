from typing import TYPE_CHECKING, cast, Sequence, List, Union, Dict, OrderedDict, Optional

from lft.consensus.messages.message import MessagePool, Message

from loopchain.blockchain.blocks import BlockProver, BlockProverType, NextRepsChangeReason
from loopchain.blockchain.blocks.v0_3 import BlockProver
from loopchain.blockchain.transactions import TransactionSerializer, TransactionVersioner
from loopchain.blockchain.types import Hash32, ExternalAddress
from loopchain.channel.channel_property import ChannelProperty
from loopchain.utils.message_queue import StubCollection

if TYPE_CHECKING:
    from loopchain.blockchain.votes.v1_0.vote import BlockVote


class InvokeRequest:
    def __init__(self, height: int,
                 transactions: OrderedDict[Hash32, 'Transaction'],
                 prev_peer_id: ExternalAddress,
                 block_hash: Hash32,
                 prev_block_hash: Hash32,
                 timestamp: int,
                 prev_votes: Sequence['BlockVote'],
                 tx_versioner: TransactionVersioner,
                 is_block_editable: bool):
        self._height: int = height
        self._timestamp: int = timestamp
        self._block_hash: Hash32 = block_hash
        self._prev_block_hash: Hash32 = prev_block_hash
        self._transactions: OrderedDict[Hash32, 'Transaction'] = transactions
        self._prev_votes: Sequence['BlockVote'] = prev_votes
        self._prev_peer_id: str = prev_peer_id.hex_hx() if prev_peer_id else ""
        self._tx_versioner: TransactionVersioner = tx_versioner
        self._is_block_editable: bool = is_block_editable

    def serialize(self) -> dict:
        prev_block_votes = self._serialize_prev_votes_except_leader()
        prev_block_validators = self._extract_validators(prev_block_votes)
        return {
            "block": {
                "blockHeight": hex(self._height),
                "blockHash": self._block_hash.hex(),
                "prevBlockHash": self._prev_block_hash.hex(),
                "timestamp": hex(self._timestamp)
            },
            "isBlockEditable": hex(self._is_block_editable),
            "transactions": self._serialize_txs(),
            "prevBlockGenerator": self._prev_peer_id,
            "prevBlockValidators": prev_block_validators,
            "prevBlockVotes": prev_block_votes
        }

    def _serialize_txs(self) -> List[Union[dict]]:
        if not self._transactions:
            return []

        transactions = []
        for tx in self._transactions.values():
            tx_serializer = TransactionSerializer.new(tx.version, tx.type(), self._tx_versioner)
            transaction = {
                "method": "icx_sendTransaction",
                "params": tx_serializer.to_full_data(tx)
            }
            transactions.append(transaction)

        return transactions

    def _serialize_prev_votes_except_leader(self) -> List[List[Union[str]]]:
        """Serialize all prev votes except leader's.

        Return example:
            [[voter_id, vote_result], ...]
        """
        prev_block_votes = []
        for vote in self._prev_votes:
            # Remove Leader's Vote
            if vote.voter_id.hex_hx() == self._prev_peer_id:
                continue

            if vote.is_none():
                vote_result = "0x2"
            elif vote.is_lazy():
                vote_result = "0x0"
            elif vote.is_real():
                vote_result = "0x1"
            else:
                raise RuntimeError("Failed to parse vote result.")

            prev_block_votes.append([vote.voter_id.hex_hx(), vote_result])

        return prev_block_votes

    def _extract_validators(self, prev_block_votes: List[List[str]]) -> List[str]:
        """Get all validators except leader."""
        if prev_block_votes:
            validators, _vote_results = zip(*prev_block_votes)
            return [validator for validator in validators]
        else:
            return []

    @classmethod
    def from_block(cls, block: 'Block'):
        header: 'BlockHeader' = block.header
        body: 'BlockBody' = block.body

        return cls(
            height=header.height,
            transactions=body.transactions,
            prev_peer_id=header.peer_id,
            block_hash=header.hash,
            prev_block_hash=header.prev_hash,
            timestamp=header.timestamp,
            prev_votes=body.prev_votes,
            tx_versioner=TransactionVersioner(),
            is_block_editable=True
        )


class InvokeData(Message):
    def __init__(self,
                 epoch_num: int,
                 round_num: int,
                 added_transactions: Dict[str, dict],
                 validators_hash: Hash32,
                 next_validators_origin: dict = None):
        """Represents a return value of Invoke Message, received from ICON-Service.

        :param epoch_num: Current epoch number
        :param round_num: Current round number
        :param added_transactions: Txs added by ICON-Service
        :param validators_hash: Current validators hash
        :param next_validators_origin: Information about next validators.
        """

        self._id: bytes = f"{epoch_num}_{round_num}".encode()
        self._epoch_num: int = epoch_num
        self._round_num: int = round_num
        self._added_transactions: Dict[str, dict] = added_transactions
        self._validators_hash: Hash32 = validators_hash

        # Additional params
        self._next_validators: Optional[list] = None
        self._next_validators_hash: Hash32 = validators_hash
        self._changed_reason: NextRepsChangeReason = NextRepsChangeReason.NoChange

        if next_validators_origin:
            self._next_validators = next_validators_origin["nextReps"]
            self._next_validators_hash = Hash32.fromhex(next_validators_origin["rootHash"], ignore_prefix=True)
            self._changed_reason = NextRepsChangeReason.convert_to_change_reason(next_validators_origin["state"])

        # Added after invoke
        self.receipts: Optional[dict] = None
        self.state_hash: Optional[Hash32] = None

    @property
    def id(self) -> bytes:
        return self._id

    @property
    def epoch_num(self) -> int:
        return self._epoch_num

    @property
    def round_num(self) -> int:
        return self._round_num

    @property
    def added_transactions(self) -> dict:
        # FIXME: Return raw data or converted one?
        return self._added_transactions

    @property
    def validators_hash(self) -> Hash32:
        return self._validators_hash

    @property
    def next_validators(self) -> Optional[List[Dict[str, str]]]:
        # TODO: need to be defined according to ICON-Service API
        return self._next_validators

    @property
    def next_validators_hash(self) -> Hash32:
        # TODO: need to be defined according to ICON-Service API
        return self._next_validators_hash

    @property
    def changed_reason(self) -> NextRepsChangeReason:
        return self._changed_reason

    @property
    def receipt_hash(self) -> Hash32:
        if not self.receipts:
            return Hash32.empty()

        block_prover = BlockProver(self.receipts, BlockProverType.Receipt)
        return block_prover.get_proof_root()

    @classmethod
    def from_dict(cls, epoch_num, round_num, query_result: dict):
        added_txs: Dict[str, dict] = query_result.get("addedTransactions")
        validators_hash: Hash32 = Hash32.fromhex(query_result.get("currentRepsHash"), ignore_prefix=True)
        next_validators_info: Optional[dict] = query_result.get("prep")

        return cls(
            epoch_num=epoch_num,
            round_num=round_num,
            added_transactions=added_txs,
            validators_hash=validators_hash,
            next_validators_origin=next_validators_info
        )

    def add_invoke_result(self, invoke_result: dict) -> 'InvokeData':
        tx_receipts_origin = invoke_result.get("txResults")
        if not isinstance(tx_receipts_origin, dict):
            receipts = {Hash32.fromhex(tx_receipt['txHash'], ignore_prefix=True): tx_receipt
                        for tx_receipt in cast(list, tx_receipts_origin)}
        else:
            receipts = tx_receipts_origin

        self.receipts = receipts
        self.state_hash = Hash32(bytes.fromhex(invoke_result.get("stateRootHash")))

        return self


class InvokePool(MessagePool):
    def get_invoke_data(self, epoch_num: int, round_num: int) -> InvokeData:
        id_ = f"{epoch_num}_{round_num}".encode()
        return self.get_message(id_)

    def prepare_invoke(self, epoch_num: int, round_num: int) -> InvokeData:
        icon_service = StubCollection().icon_score_stubs[ChannelProperty().name]  # FIXME SINGLETON!

        preinvoke_result = self._preinvoke_temp()  # FIXME: Do communicate with ICON-Service
        invoke_data: InvokeData = InvokeData.from_dict(
            epoch_num=epoch_num, round_num=round_num, query_result=preinvoke_result
        )
        self.add_message(invoke_data)

        return invoke_data

    def invoke(self, epoch_num: int, round_num: int, invoke_request: InvokeRequest) -> InvokeData:
        """Originated from `Blockchain.score_invoke`."""

        invoke_data: InvokeData = self.get_invoke_data(epoch_num, round_num)

        icon_service = StubCollection().icon_score_stubs[ChannelProperty().name]  # FIXME SINGLETON!
        invoke_result_dict: dict = icon_service.sync_task().invoke(invoke_request.serialize())

        invoke_data.add_invoke_result(invoke_result=invoke_result_dict)

        return invoke_data

    def _preinvoke_temp(self) -> dict:
        return {
            "addedTransactions": {
                "6804dd2ccd9a9d17136d687838aa09e02334cd4afa964d75993f18991ee874de": {
                    "version": "0x3",
                    "timestamp": "0x563a6cf330136",
                    "dataType": "base",
                    "data": {
                        "prep": {
                            "incentive": "0x1",
                            "rewardRate": "0x1",
                            "totalDelegation": "0x3872423746291",
                            "value": "0x7800000"
                        }
                    }
                }
            },
            "currentRepsHash": "1d04dd2ccd9a9d14416d6878a8aa09e02334cd4afa964d75993f2e991ee874de",
            "prep": {
                "nextReps": [
                    {
                        "id": "hx86aba2210918a9b116973f3c4b27c41a54d5dafe",
                        "p2pEndpoint": "123.45.67.89:7100"
                    },
                    {
                        "id": "hx13aca3210918a9b116973f3c4b27c41a54d5dad1",
                        "p2pEndPoint": "210.34.56.17:7100"
                    }
                ],
                "irep": "0x1",
                "state": "0x0",
                "rootHash": "c7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
            }
        }
