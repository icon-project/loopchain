from typing import TYPE_CHECKING, cast, Sequence, List, Union, Dict, OrderedDict, Optional

from lft.consensus.messages.message import MessagePool, Message

from loopchain.blockchain.blocks import BlockProverType
from loopchain.blockchain.blocks.v0_3 import BlockProver
from loopchain.blockchain.transactions import TransactionSerializer, TransactionVersioner
from loopchain.blockchain.types import Hash32, ExternalAddress
from loopchain.channel.channel_property import ChannelProperty
from loopchain.utils.icon_service import convert_params, ParamType
from loopchain.utils.message_queue import StubCollection

if TYPE_CHECKING:
    from loopchain.blockchain.blocks.v1_0 import Block
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


class PreInvokeResponse:
    def __init__(self,
                 added_transactions,
                 validators_hash: Hash32):
        self._added_txs = added_transactions
        self._validators_hash: Hash32 = validators_hash

    def __repr__(self):
        return f"{self.__class__.__name__}(" \
            f"added_transactions={self._added_txs}," \
            f"validators_hash={self._validators_hash})"

    @property
    def added_transactions(self):
        return self._added_txs

    @property
    def validators_hash(self) -> Hash32:
        return self._validators_hash

    @classmethod
    def new(cls, pre_invoke_result: dict):
        # FIXME: `currentRepsHash` and `addedTransactions` may always be returned after Rev.6.
        added_txs: Dict[str, dict] = pre_invoke_result.get("addedTransactions", {})
        validators_hash = pre_invoke_result.get("currentRepsHash")
        validators_hash = Hash32.fromhex(validators_hash, ignore_prefix=True) \
            if validators_hash else ChannelProperty().crep_root_hash

        return cls(
            added_transactions=added_txs,
            validators_hash=validators_hash
        )


class InvokeData(Message):
    def __init__(self,
                 epoch_num: int,
                 round_num: int,
                 height: int,
                 receipts: list,
                 validators_hash: Hash32,
                 state_root_hash: Hash32,
                 next_validators_origin: dict = None):
        """Represents a return value of Invoke Message, received from ICON-Service.

        :param epoch_num: Current epoch number
        :param round_num: Current round number
        :param height: Height
        :param validators_hash: Current validators hash
        :param next_validators_origin: Information about next validators.
        """

        self._id: bytes = f"{epoch_num}_{round_num}".encode()
        self._epoch_num: int = epoch_num
        self._round_num: int = round_num
        self._height = height
        self._receipts: list = receipts
        self._state_hash: Optional[Hash32] = state_root_hash

        if next_validators_origin:
            reps = [ExternalAddress.fromhex(rep["id"]) for rep in next_validators_origin["nextReps"]]
            block_prover = BlockProver((rep.extend() for rep in reps), BlockProverType.Rep)
            self._next_validators_hash = block_prover.get_proof_root()
        else:
            self._next_validators_hash: Hash32 = validators_hash

    def __repr__(self):
        return f"{self.__class__.__name__}(" \
            f"epoch_num={self._epoch_num}," \
            f"round_num={self._round_num})"

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
    def height(self) -> int:
        return self._height

    @property
    def state_hash(self) -> Hash32:
        return self._state_hash

    @property
    def next_validators_hash(self) -> Hash32:
        # TODO: need to be defined according to ICON-Service API
        return self._next_validators_hash

    @property
    def receipt_hash(self) -> Hash32:
        if not self._receipts:
            return Hash32.empty()

        block_prover = BlockProver(self._receipts, BlockProverType.Receipt)
        return block_prover.get_proof_root()

    @classmethod
    def new(cls, epoch_num, round_num,
            height: int,
            current_validators_hash: Hash32,
            invoke_result: dict):
        """Create Invoke Data from PreInvoke result."""
        state_hash = Hash32(bytes.fromhex(invoke_result.get("stateRootHash")))
        next_validators_info: Optional[dict] = invoke_result.get("prep")
        receipts: list = invoke_result.get("txResults")

        return cls(
            epoch_num=epoch_num,
            round_num=round_num,
            height=height,
            receipts=receipts,
            validators_hash=current_validators_hash,
            state_root_hash=state_hash,
            next_validators_origin=next_validators_info
        )


class InvokePool(MessagePool):
    def __init__(self, blockchain):
        super(InvokePool, self).__init__()
        self._blockchain = blockchain

    def get_invoke_data(self, epoch_num: int, round_num: int) -> InvokeData:
        id_ = f"{epoch_num}_{round_num}".encode()

        return cast(InvokeData, self.get_message(id_))

    def prepare_invoke(self, block_height: int, block_hash: Hash32) -> PreInvokeResponse:
        icon_service = StubCollection().icon_score_stubs[ChannelProperty().name]  # FIXME SINGLETON!

        request = {
            "blockHeight": hex(block_height),
            "blockHash": block_hash.hex()
        }
        pre_invoke_result = cast(dict, icon_service.sync_task().pre_invoke(request))

        return PreInvokeResponse.new(pre_invoke_result)

    def invoke(self, block: 'Block') -> InvokeData:
        """Originated from `Blockchain.score_invoke`."""

        invoke_request = InvokeRequest.from_block(block=block)

        icon_service = StubCollection().icon_score_stubs[ChannelProperty().name]  # FIXME SINGLETON!
        invoke_result_dict: dict = icon_service.sync_task().invoke(invoke_request.serialize())

        invoke_data = InvokeData.new(
            epoch_num=block.header.epoch,
            round_num=block.header.round,
            height=block.header.height,
            current_validators_hash=block.header.validators_hash,
            invoke_result=invoke_result_dict
        )
        self.add_message(invoke_data)

        self._process_invoke_results_legacy(block, invoke_result_dict)

        return invoke_data

    def _process_invoke_results_legacy(self, block: 'Block', invoke_result_dict: dict):
        """Temporary"""

        tx_receipts = invoke_result_dict["txResults"]
        for tx_receipt in tx_receipts:
            tx_receipt["blockHash"] = block.header.hash.hex()

        self._blockchain.invoke_results[block.header.hash] = (tx_receipts, None)

    def genesis_invoke(self, block: 'Block') -> InvokeData:
        method = "icx_sendTransaction"
        transactions = []
        tx_versioner = TransactionVersioner()
        for tx in block.body.transactions.values():
            tx_serializer = TransactionSerializer.new(tx.version, tx.type(), tx_versioner)
            transaction = {
                "method": method,
                "params": {
                    "txHash": tx.hash.hex()
                },
                "genesisData": tx_serializer.to_full_data(tx)
            }
            transactions.append(transaction)

        request = {
            'block': {
                'blockHeight': block.header.height,
                'blockHash': block.header.hash.hex(),
                'timestamp': block.header.timestamp
            },
            'transactions': transactions
        }
        request = convert_params(request, ParamType.invoke)
        stub = StubCollection().icon_score_stubs[ChannelProperty().name]
        invoke_result_dict: dict = stub.sync_task().invoke(request)

        invoke_data: InvokeData = InvokeData.new(
            epoch_num=block.header.epoch,
            round_num=block.header.round,
            height=block.header.height,
            current_validators_hash=block.header.validators_hash,
            invoke_result=invoke_result_dict
        )
        self.add_message(invoke_data)

        return invoke_data
