from collections import OrderedDict
from typing import List

import pytest

from loopchain.blockchain.blocks import NextRepsChangeReason
from loopchain.blockchain.invoke_result import InvokeRequest, InvokeData, InvokePool
from loopchain.blockchain.transactions import Transaction, TransactionVersioner, TransactionSerializer
from loopchain.blockchain.types import ExternalAddress, Hash32, Signature
from loopchain.blockchain.votes.v1_0.vote import BlockVote
from testcase.unittest.blockchain.conftest import TxFactory


@pytest.fixture
def icon_query() -> dict:
    """Get queried data from ICON-Service.

    TODO: Check that the all data have valid key and value, especially hash prefix!
    """

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


@pytest.fixture
def icon_invoke() -> dict:
    """Get invoke result from ICON-Service.

    TODO: Check that the all data have valid key and value, especially hash prefix!
    """

    return {
        "txResults": [
            {
                "status": "0x1",
                "txHash": "c71303ef8543d04b5dc1ba6579132b143087c68db1b2168786408fcbce568238",
                "txIndex": "0x0",
                "blockHeight": "0x1234",
                "blockHash": "c71303ef8543d04b5dc1ba6579132b143087c68db1b2168786408fcbce568238",
                "cumulativeStepUsed": "0x1234",
                "stepUsed": "0x1234",
                "stepPrice": "0x100",
                "scoreAddress": "cxb0776ee37f5b45bfaea8cff1d8232fbb6122ec32"
            }
        ],
        "stateRootHash": "c71303ef8543d04b5dc1ba6579132b143087c68db1b2168786408fcbce568238",
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
        "prep": {
            "preps": [
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
        print("Invoke request: ", invoke_request_dict)

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
                data_id=vote_result,
                commit_id=self.prev_block_hash,
                voter_id=validator,
                epoch_num=1,
                round_num=1,
                state_hash=Hash32.new(),
                receipt_hash=Hash32.new(),
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


class TestInvokeData:
    def test_created_from_query_dict(self, icon_query: dict):
        # WHEN I create InvokeData by using the queried data
        epoch_num = 1
        round_num = 1
        invoke_data: InvokeData = InvokeData.from_dict(
            epoch_num=epoch_num,
            round_num=round_num,
            query_result=icon_query
        )

        # THEN It should contain required data
        assert invoke_data.epoch_num == epoch_num
        assert invoke_data.round_num == epoch_num
        assert invoke_data.added_transactions == icon_query["addedTransactions"]
        assert invoke_data.validators_hash.hex() == icon_query["currentRepsHash"]

    def test_validators_changed(self, icon_query: dict):
        # GIVEN I queried and validators changed
        assert "prep" in icon_query

        # WHEN I create InvokeData by using the queried data
        invoke_data: InvokeData = InvokeData.from_dict(
            epoch_num=1,
            round_num=1,
            query_result=icon_query
        )
        # THEN It should tell why validators list has been changed
        reason = invoke_data.changed_reason
        assert isinstance(reason, NextRepsChangeReason)
        assert reason != NextRepsChangeReason.NoChange

        # AND next validators and theirs hash should be exist
        assert invoke_data.next_validators == icon_query["prep"]["nextReps"]
        assert invoke_data.next_validators_hash.hex() == icon_query["prep"]["rootHash"]

    def test_validators_not_changed(self, icon_query: dict):
        # GIVEN I queried and no changes in validators list
        icon_query.pop("prep")
        assert "prep" not in icon_query

        # WHEN I create InvokeData by using the queried data
        invoke_data: InvokeData = InvokeData.from_dict(
            epoch_num=1,
            round_num=1,
            query_result=icon_query
        )

        # THEN Prep list is not changed
        reason = invoke_data.changed_reason
        assert isinstance(reason, NextRepsChangeReason)
        assert reason == NextRepsChangeReason.NoChange

        # AND There are no next validators
        assert not invoke_data.next_validators
        assert invoke_data.next_validators_hash.hex() == invoke_data.validators_hash.hex() == icon_query["currentRepsHash"]

    def test_add_invoke_result(self, icon_query: dict, icon_invoke: dict):
        # GIVEN I queried and got data
        invoke_data: InvokeData = InvokeData.from_dict(
            epoch_num=1,
            round_num=1,
            query_result=icon_query
        )

        # AND It should not contain receipts and its hash at first,
        assert not invoke_data.receipts
        assert invoke_data.receipt_hash == Hash32.empty()

        # AND neither state hash.
        assert not invoke_data.state_hash

        # WHEN I add invoke result message
        invoke_data.add_invoke_result(invoke_result=icon_invoke)

        # THEN receipt_hash should be generated
        assert "txResults" in icon_invoke
        assert invoke_data.receipts
        assert invoke_data.receipt_hash != Hash32.empty()

        # AND invoke data should contain state hash
        assert invoke_data.state_hash.hex() == icon_invoke["stateRootHash"]


class TestInvokePool:
    @pytest.fixture
    def invoke_pool(self):
        return InvokePool()

    @pytest.mark.xfail(reason="Resolve ICON stub object in invoke pool first!")
    def test_get_invoke_data(self, icon_query: dict, icon_invoke: dict, invoke_pool):
        assert False
