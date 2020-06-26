from collections import OrderedDict
from typing import List, Callable

import pytest

from loopchain.blockchain import BlockBuilder
from loopchain.blockchain.invoke_result import InvokeRequest, InvokeData, InvokePool, PreInvokeResponse
from loopchain.blockchain.transactions import Transaction, TransactionVersioner, TransactionSerializer
from loopchain.blockchain.types import ExternalAddress, Hash32, Signature
from loopchain.blockchain.votes.v1_0.vote import BlockVote
from loopchain.channel.channel_property import ChannelProperty
from loopchain.scoreservice import IconScoreInnerStub
from loopchain.utils.message_queue import StubCollection
from testcase.unittest.blockchain.conftest import TxFactory


class TestInvokeRequest:
    """
    Invoke Request Message Example:
    ```
    {
       "block":{
          "blockHeight":"0x3",
          "blockHash":"02a8c0f70389f327e322c2536dd26e7cbbc5fa943d6c4777fd1915f284f77e71",
          "prevBlockHash":"ea2254afbeaa13c73b6f366bfc7621e2a155df9e3ee1e1e7c00df5345c84a7af",
          "timestamp":"0x5a3b01841da3a"
       },
       "isBlockEditable":"0x0",
       "transactions":[
          {
             "method":"icx_sendTransaction",
             "params":{
                "version":"0x3",
                "from":"hx5a05b58a25a1e5ea0f1d5715e1f655dffc1fb30a",
                "to":"hx86aba2210918a9b116973f3c4b27c41a54d5dafe",
                "stepLimit":"0xf4240",
                "timestamp":"0x5a3b018265458",
                "nid":"0x3",
                "value":"0x10f0cf064dd59200000",
                "signature":"4LTa9BF8C4eJ6sFEwjPwCMEecuMXfDzQT2hggpW+0a1N+BBPlWRlibTkgyLiaBwdY9rf5u1WevBM6T51+UF/UAE=",
                "txHash":"4d3cd87939fb0240317e409350edb9e436a1a56b152949a1cb9917aa48f1b099"
             }
          },
          ...
       ],
       "prevBlockGenerator":"hx86aba2210918a9b116973f3c4b27c41a54d5dafe",
       "prevBlockValidators":[
          "hx9f049228bade72bc0a3490061b824f16bbb74589",
          "hx6435405122df9fe5187d659588beccdf7aee8557",
          "hx475bfec4178f3abc88c959faa2e6384e6b409c8f"
       ],
       "prevBlockVotes":[
          [
             "hx9f049228bade72bc0a3490061b824f16bbb74589",
             "0x0"
          ],
          [
             "hx6435405122df9fe5187d659588beccdf7aee8557",
             "0x1"
          ],
          [
             "hx475bfec4178f3abc88c959faa2e6384e6b409c8f",
             "0x2"
          ]
       ]
    }
    ```
    """
    expected_block_hash = "02a8c0f70389f327e322c2536dd26e7cbbc5fa943d6c4777fd1915f284f77e71"
    expected_prev_block_hash = "ea2254afbeaa13c73b6f366bfc7621e2a155df9e3ee1e1e7c00df5345c84a7af"
    expected_prev_peer_id = "hx86aba2210918a9b116973f3c4b27c41a54d5dafe"

    block_hash = Hash32.fromhex(expected_block_hash, ignore_prefix=True)
    prev_block_hash = Hash32.fromhex(expected_prev_block_hash, ignore_prefix=True)
    prev_peer_id = ExternalAddress.fromhex(expected_prev_peer_id)

    @pytest.mark.parametrize("block_height, expected_block_height", [(0, "0x0"), (1, "0x1")], ids=["height 0", "height 1"])
    @pytest.mark.parametrize("timestamp, expected_timestamp", [(0, "0x0"), (1, "0x1")], ids=["timestamp0", "timestamp1"])
    @pytest.mark.parametrize("is_block_editable, expected_block_editable", [(True, "0x1"), (False, "0x0")], ids=["editable", "not_editable"])
    def test_invoke_basic_params(self, block_height, expected_block_height,
                                 timestamp: int, expected_timestamp: hex,
                                 is_block_editable: bool, expected_block_editable):
        """Tests serialization of basic params

        target params:
            `blockHeight`, `timestamp` and `isBlockEditable`.
        """
        # GIVEN I expected Invoke Message below
        expected_request = {
            "block": {
                "blockHeight": expected_block_height,
                "blockHash": self.expected_block_hash,
                "prevBlockHash": self.expected_prev_block_hash,
                "timestamp": expected_timestamp
            },
            "isBlockEditable": expected_block_editable,
            "transactions": [],
            "prevBlockGenerator": self.expected_prev_peer_id,
            "prevBlockValidators": [],
            "prevBlockVotes": []
        }

        # WHEN I made request
        invoke_request_dict = InvokeRequest(
            height=block_height,
            transactions=[],
            prev_peer_id=self.prev_peer_id,
            block_hash=self.block_hash,
            prev_block_hash=self.prev_block_hash,
            timestamp=timestamp,
            prev_votes=[],
            tx_versioner=TransactionVersioner(),
            is_block_editable=is_block_editable
        ).serialize()

        # THEN Invoke Message should be identical as I expected
        assert invoke_request_dict == expected_request

    def test_txs(self, tx_factory: TxFactory):
        """Tests serialization of transactions."""
        # GIVEN I have tx data
        dumped_txs = [
            {
                "method": "icx_sendTransaction",
                "params": {
                    "version": "0x3",
                    "from": "hx5a05b58a25a1e5ea0f1d5715e1f655dffc1fb30a",
                    "to": "hx86aba2210918a9b116973f3c4b27c41a54d5dafe",
                    "stepLimit": "0xf4240",
                    "timestamp": "0x5a3b018265458",
                    "nid": "0x3",
                    "value": "0x10f0cf064dd59200000",
                    "signature": "4LTa9BF8C4eJ6sFEwjPwCMEecuMXfDzQT2hggpW+0a1N+BBPlWRlibTkgyLiaBwdY9rf5u1WevBM6T51+UF/UAE=",
                    "txHash": "4d3cd87939fb0240317e409350edb9e436a1a56b152949a1cb9917aa48f1b099"
                }
            },
            {
                "method": "icx_sendTransaction",
                "params": {
                    "version": "0x3",
                    "from": "hx5a05b58a25a1e5ea0f1d5715e1f655dffc1fb30a",
                    "to": "hx9f049228bade72bc0a3490061b824f16bbb74589",
                    "stepLimit": "0xf4240",
                    "timestamp": "0x5a3b018271884",
                    "nid": "0x3",
                    "value": "0x10f0cf064dd59200000",
                    "signature": "KNsjwClgpGknXRspkeka2Osl/SwFeCaNIj3+heI/Qj4wn8lkABP5AIntnNoqwhZ3CHypsiuYuIf9PfzvySv6JAA=",
                    "txHash": "fcd735c46d9533ff9636477402026da910f8aec2880d13cdf0ca29abc0353cbe"
                }
            }
        ]
        tx_versioner = TransactionVersioner()
        tx_serializer = TransactionSerializer.new("0x3", "", tx_versioner)
        transactions = OrderedDict()
        for dumped_tx in dumped_txs:
            tx: Transaction = tx_serializer.from_(dumped_tx["params"])
            transactions[tx.hash] = tx

        # AND I expected Invoke Message below
        expected_request = {
            "block": {
                "blockHeight": "0x1",
                "blockHash": self.expected_block_hash,
                "prevBlockHash": self.expected_prev_block_hash,
                "timestamp": "0x1"
            },
            "isBlockEditable": "0x1",
            "transactions": dumped_txs,
            "prevBlockGenerator": self.expected_prev_peer_id,
            "prevBlockValidators": [],
            "prevBlockVotes": []
        }

        # WHEN I create InvokeRequest
        invoke_request_dict = InvokeRequest(
            height=1,
            transactions=transactions,
            prev_peer_id=self.prev_peer_id,
            block_hash=self.block_hash,
            prev_block_hash=self.prev_block_hash,
            timestamp=1,
            prev_votes=[],
            tx_versioner=tx_versioner,
            is_block_editable=True
        ).serialize()
        print("Invoke request: ", invoke_request_dict)

        # THEN Invoke Message should be identical as I expected
        assert invoke_request_dict == expected_request

    def test_vote_and_leaders(self):
        """Tests serialization of votes and validators."""
        # GIVEN There're validators
        validators: List[ExternalAddress] = [
            ExternalAddress.fromhex("hx86aba2210918a9b116973f3c4b27c41a54d5dafe"),
            ExternalAddress.fromhex("hx9f049228bade72bc0a3490061b824f16bbb74589"),
            ExternalAddress.fromhex("hx6435405122df9fe5187d659588beccdf7aee8557"),
            ExternalAddress.fromhex("hx475bfec4178f3abc88c959faa2e6384e6b409c8f")
        ]
        leader_id: ExternalAddress = validators[0]

        # AND Validators voted or not
        vote_results: List[Hash32] = [
            Hash32.fromhex("0x02a8c0f70389f327e322c2536dd26e7cbbc5fa943d6c4777fd1915f284f77e71"),  # Leader upvotes
            Hash32.fromhex("0x02a8c0f70389f327e322c2536dd26e7cbbc5fa943d6c4777fd1915f284f77e71"),  # Valdator1 upvotes
            BlockVote.NoneVote,  # Valdator2 downvotes
            BlockVote.LazyVote,  # Valdator3 disconnected
        ]
        # AND I received votes of them
        prev_votes: List[BlockVote] = [
            BlockVote(
                height=1,
                data_id=vote_result,
                commit_id=self.prev_block_hash,
                voter_id=validator,
                epoch_num=1,
                round_num=1,
                state_hash=Hash32.new(),
                receipt_hash=Hash32.new(),
                next_validators_hash=Hash32.new(),
                timestamp=1,
                signature=Signature.new()
            ) for validator, vote_result in zip(validators, vote_results)
        ]

        # AND I expected Invoke Message below
        expected_request = {
            "block": {
                "blockHeight": "0x1",
                "blockHash": self.expected_block_hash,
                "prevBlockHash": self.expected_prev_block_hash,
                "timestamp": "0x1"
            },
            "isBlockEditable": "0x1",
            "transactions": [],
            # prevBlockBlockGenerator should be the leader
            "prevBlockGenerator": "hx86aba2210918a9b116973f3c4b27c41a54d5dafe",
            # AND prevBlockValidators should contain all of validators except leader
            "prevBlockValidators": [
                "hx9f049228bade72bc0a3490061b824f16bbb74589",
                "hx6435405122df9fe5187d659588beccdf7aee8557",
                "hx475bfec4178f3abc88c959faa2e6384e6b409c8f"
            ],
            # AND prevBlockVotes should contain all of validators and votes of them, except of leader's
            "prevBlockVotes": [
                ["hx9f049228bade72bc0a3490061b824f16bbb74589", "0x1"],  # Validator1 upvotes
                ["hx6435405122df9fe5187d659588beccdf7aee8557", "0x2"],  # Validator2 downvotes
                ["hx475bfec4178f3abc88c959faa2e6384e6b409c8f", "0x0"]   # Validator3 timed out
            ]
        }

        # WHEN I made InvokeRequest
        invoke_request_dict = InvokeRequest(
            height=1,
            transactions=[],
            prev_peer_id=leader_id,
            block_hash=self.block_hash,
            prev_block_hash=self.prev_block_hash,
            timestamp=1,
            prev_votes=prev_votes,
            tx_versioner=TransactionVersioner(),
            is_block_editable=True
        ).serialize()
        print("Invoke request: ", invoke_request_dict)

        # THEN Invoke Message should be identical as I expected
        assert invoke_request_dict == expected_request


class TestPreInvokeResponse:
    def test_from_dict(self, icon_preinvoke):
        response = PreInvokeResponse.from_dict(icon_preinvoke)

        assert response.validators_hash.hex_0x() == "0x1d04dd2ccd9a9d14416d6878a8aa09e02334cd4afa964d75993f2e991ee874de"
        assert response.added_transactions == {
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
        }


class TestInvokeData:
    epoch_num = 1
    round_num = 1
    height = 1
    current_validators_hash = Hash32.fromhex("0xc71303ef8543d04b5dc1ba6579132b143087c68db1b2168786408fcbce568238")

    @pytest.fixture
    def invoke_data_factory(self) -> Callable[..., InvokeData]:
        def _(_icon_invoke: dict, **kwargs):
            return InvokeData.new(
                epoch_num=kwargs.get("epoch_num", TestInvokeData.epoch_num),
                round_num=kwargs.get("round_num", TestInvokeData.round_num),
                height=kwargs.get("height", TestInvokeData.height),
                current_validators_hash=kwargs.get("current_validators_hash", TestInvokeData.current_validators_hash),
                invoke_result=_icon_invoke
            )

        return _

    def _get_reps_root_hash(self, prep) -> Hash32:
        preps = prep.get("nextReps")
        preps = [ExternalAddress.fromhex(prep["id"]) for prep in preps]

        from loopchain.blockchain.blocks import BlockProverType
        from loopchain.blockchain.blocks.v0_3 import BlockProver
        block_prover = BlockProver((rep.extend() for rep in preps), BlockProverType.Rep)
        return block_prover.get_proof_root()

    def test_next_validators_hash_equals_current_validators_hash_if_validators_not_changed(self, invoke_data_factory, icon_invoke):
        # GIVEN Prep is not changed
        icon_invoke.pop("prep")
        assert "prep" not in icon_invoke

        # WHEN I created InvokeData
        invoke_result = invoke_data_factory(icon_invoke)

        # THEN next validators hash should be current validators hash
        assert invoke_result.next_validators_hash == TestInvokeData.current_validators_hash

    def test_validators_changed(self, invoke_data_factory, icon_invoke):
        # GIVEN I call Invoke and validators changed
        assert "prep" in icon_invoke
        expected_next_validators_hash = self._get_reps_root_hash(icon_invoke["prep"])

        # WHEN I created InvokeData
        invoke_data: InvokeData = invoke_data_factory(icon_invoke)

        # THEN next_validators_hash should be differ with
        assert invoke_data.next_validators_hash == expected_next_validators_hash != TestInvokeData.current_validators_hash


class TestInvokePool:
    channel_name = "test"

    @pytest.fixture
    def genesis_block(self, tx_factory):
        from loopchain.blockchain.blocks import v1_0

        tx_versioner = TransactionVersioner()
        signer = pytest.SIGNERS[0]

        block_builder = BlockBuilder.new(v1_0.version, tx_versioner)
        block_builder.peer_id = ExternalAddress.empty()
        block_builder.fixed_timestamp = 0
        block_builder.prev_votes = []
        block_builder.prev_state_hash = Hash32.empty()

        from loopchain.blockchain.transactions import genesis
        tx = tx_factory(genesis.version)
        block_builder.transactions[tx.hash] = tx

        block_builder.height = 0
        block_builder.prev_hash = Hash32.empty()
        block_builder.signer = None

        peer_id = ExternalAddress.fromhex_address(signer.address)
        block_builder.validators_hash = Hash32.empty()
        block_builder.next_validators = [peer_id]

        block_builder.epoch = 0
        block_builder.round = 0

        return block_builder.build()

    @pytest.fixture
    def invoke_pool(self):
        return InvokePool()

    @pytest.fixture(autouse=True)
    def mock_channel_name(self):
        ChannelProperty().name = TestInvokePool.channel_name

        yield

        ChannelProperty().name = None

    @pytest.fixture
    def icon_score_stub(self, mocker, icon_preinvoke, icon_invoke):
        stub = mocker.MagicMock(IconScoreInnerStub)
        task = mocker.MagicMock()
        stub.sync_task.return_value = task
        task.pre_invoke.return_value = icon_preinvoke
        task.invoke.return_value = icon_invoke

        return stub

    @pytest.fixture(autouse=True)
    def mock_stub_collection(self, icon_score_stub):
        StubCollection().icon_score_stubs[ChannelProperty().name] = icon_score_stub

        yield

        StubCollection().icon_score_stubs = {}

    def test_preinvoke(self, icon_preinvoke, invoke_pool):
        block_height = 1
        block_hash = Hash32.new()

        # WHEN I call prepare invoke
        response = invoke_pool.prepare_invoke(
            block_height=block_height,
            block_hash=block_hash
        )

        # FIXME
        assert isinstance(response, PreInvokeResponse)

    def test_genesis_invoke(self, invoke_pool, genesis_block: 'Block'):
        # GIVEN I have no invoke data
        assert not invoke_pool._messages

        # AND Suppose that ICON-Service returns below as a result of genesis invoke
        StubCollection().icon_score_stubs[ChannelProperty().name].sync_task().invoke.return_value = {
            "txResults": [
                {"txHash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                 "blockHeight": "0x0",
                 "blockHash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                 "txIndex": "0x0",
                 "stepUsed": "0x0",
                 "stepPrice": "0x0",
                 "cumulativeStepUsed": "0x0",
                 "status": "0x1"}
            ],
            "stateRootHash": "4444444444444444444444444444444444444444444444444444444444444444"
        }

        # WHEN I call invoke as a genesis block
        invoke_pool.genesis_invoke(genesis_block)

        # THEN The pool must have genesis invoke result
        genesis_invoke_result = invoke_pool.get_invoke_data(genesis_block.header.epoch, genesis_block.header.round)
        assert genesis_invoke_result

    @pytest.mark.xfail
    def test_preinvoke_before_rev6(self, icon_preinvoke, icon_invoke: dict, invoke_pool):
        assert False

    @pytest.mark.xfail(reason="Resolve ICON stub object in invoke pool first!")
    def test_get_invoke_data(self, icon_preinvoke, icon_invoke: dict, invoke_pool):
        assert False
