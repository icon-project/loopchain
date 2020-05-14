from loopchain.blockchain.transactions import TransactionVersioner
from loopchain.blockchain.transactions.v3 import TransactionSerializer
from loopchain.blockchain.blocks.v1_0.block import Block


class TestBlockSerializer:
    def test_block_deserialized(self):
        # GIVEN I got a serialized Block
        dumped_block = {
            "!type": "loopchain.blockchain.blocks.v1_0.block.Block",
            "!data": {
                "version": "1.0",
                "hash": "0x44428b1ddb2df7ddec8a21065f0026258c8916811824e35d9bffabd2a84eaa5c",
                "prevHash": "0x0082d7e7375b2ef018539264385156e893661dfaee7cde9978a166e79a7298de",
                "prevVotesHash": "0x05e9748ddac68a0e7d30fbb3a9ababfd6059a55f93f3a2104bd7049b1476bf07",
                "transactionsHash": "0xe0da028a16782afce69de107f0ded167d2de1b3ba89ff79ed735108aa52c0502",
                "prevStateHash": "0x6010335989c6608ae9546a4b2c31c585fc0496e223a667dc0d3157aaa748d251",
                "prevReceiptsHash": "0x3f6201e950389b18f5a3f32e3e805d592d6cc81cf55658bd3b149a863f206561",
                "validatorsHash": "0xde227abb65ad6bd5f55f710dfae635922c7bc1ca040d1f2b13da2507968a7b03",
                "nextValidatorsHash": "0xde227abb65ad6bd5f55f710dfae635922c7bc1ca040d1f2b13da2507968a7b03",
                "prevLogsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000"
                                 "0000000000000000000000000000000000000000000000000000000000000000000000000"
                                 "0000000000000000000000000000000000000000000000000000000000000000000000000"
                                 "0000000000000000000000000000000000000000000000000000000000000000000000000"
                                 "0000000000000000000000000000000000000000000000000000000000000000000000000"
                                 "0000000000000000000000000000000000000000000000000000000000000000000000000"
                                 "0000000000000000000000000000000000000000000000000000000000000000000000000000",
                "timestamp": "0x58340e9b30db0",
                "height": "0x1",
                "leader": "hx86aba2210918a9b116973f3c4b27c41a54d5dafe",
                "epoch": "0x1",
                "round": "0x1",
                "signature": "6qvHArp8g7YqtJUC12EK2QxndkHQQBXteS/7SYSN4gIry3ZXmbwptg2lukcA4tiu8sksFB0hEIuQjCRtkXEY/gE=",
                "transactions": [
                    {
                        "version": "0x3",
                        "from": "hx5a05b58a25a1e5ea0f1d5715e1f655dffc1fb30a",
                        "to": "hx670e692ffd3d5587c36c3a9d8442f6d2a8fcc795",
                        "value": "0xde0b6b3a7640000",
                        "stepLimit": "0x3000000",
                        "timestamp": "0x58aef94710473",
                        "nonce": "0x0",
                        "nid": "0x3",
                        "dataType": "message",
                        "data": "0x68656c6c6f",
                        "signature": "0tVS9OYKWvR0Wb1HZtaXfFWB7Jx6iFHA6dGsxm0"
                                     "r4j5TAV/J3ZKs57rwAo4eWuumc0HXd8yBG/t3gqpairgQsAE=",
                        "txHash": "9c613f5a30bcd54adbe112d51cccf3a4360caf4dca00db9f143edbaaa7c68bf7"
                    }
                ],
                "prevVotes": [
                    {
                        "validator": "hx9f049228bade72bc0a3490061b824f16bbb74589",
                        "timestamp": "0x58b01eba4c3fe",
                        "blockHeight": "0x16",
                        "blockHash": "0x0399e62d77438f940dd207a2ba4593d2b231214606140c0ee6fa8f4fa7ff1d3c",
                        "commitHash": "0x0399e62d77438f940dd207a2ba4593d2b231214606140c0ee6fa8f4fa7ff1d3d",
                        "stateHash": "0x0399e62d77438f940dd207a2ba4593d2b231214606140c0ee6fa8f4fa7ff1d3e",
                        "receiptHash": "0x0399e62d77438f940dd207a2ba4593d2b231214606140c0ee6fa8f4fa7ff1d3f",
                        "epoch": "0x2",
                        "round": "0x1",
                        "signature": "aC8qGOAO5Fz/lNVZW5nHdR8MiNj5WaDr+2IimKiYJ9dAXLQoaolOU/"
                                     "Zmefp9L1lTxAAvbkmWCZVtQpj1lMHClQE="
                    }
                ]
            }
        }

        # WHEN I deserialized it
        block: Block = Block.deserialize(dumped_block)
        block_data = dumped_block["!data"]

        # Then all properties of block header must be same
        header = block._header
        assert header.version == block_data["version"]
        assert hex(header.epoch) == block_data["epoch"]
        assert header.hash.hex_0x() == block_data["hash"]
        assert header.signature.to_base64str() == block_data["signature"]
        assert hex(header.height) == block_data["height"]
        assert header.peer_id.hex_hx() == block_data["leader"]
        assert header.prev_hash.hex_0x() == block_data["prevHash"]
        assert hex(header.timestamp) == block_data["timestamp"]
        assert header.next_validators_hash.hex_0x() == block_data["nextValidatorsHash"]
        assert header.prev_logs_bloom.hex_0x() == block_data["prevLogsBloom"]
        assert header.prev_receipts_hash.hex_0x() == block_data["prevReceiptsHash"]
        assert header.prev_state_hash.hex_0x() == block_data["prevStateHash"]
        assert header.prev_votes_hash.hex_0x() == block_data["prevVotesHash"]
        assert hex(header.round) == block_data["round"]
        assert header.transactions_hash.hex_0x() == block_data["transactionsHash"]
        assert header.validators_hash.hex_0x() == block_data["validatorsHash"]

        # AND all properties of block body must be same
        body = block._body
        assert body.prev_votes == block_data["prevVotes"]

        # AND also transactions
        for deserialized_tx_hash_and_tx, orig_tx in zip(body.transactions.items(), block_data["transactions"]):
            des_hash, des_tx = deserialized_tx_hash_and_tx
            serializer = TransactionSerializer.new(des_tx.version, des_tx.type(), TransactionVersioner())
            dumped_tx = serializer.to_full_data(des_tx)

            assert dumped_tx == orig_tx
