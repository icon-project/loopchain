# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import logging
import json
import unittest

from loopchain.utils import loggers
from loopchain.utils.icon_service import convert_params, ParamType
from tests.unit import test_util

loggers.set_preset_type(loggers.PresetType.develop)
loggers.update_preset()


class TestConverter(unittest.TestCase):

    def setUp(self):
        test_util.print_testname(self._testMethodName)

    def tearDown(self):
        pass

    def test_invoke(self):
        question = {
            "block": {
                "block_height": 1000,
                "block_hash": "0xa7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
                "time_stamp": "1234567890",
                "prevBlockHash": "0xb7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
            },
            "transactions": [{
                "method": "icx_sendTransaction",
                "params": {
                    "version": "0x3",
                    "from": "hxbe258ceb872e08851f1f59694dac2558708ece11",
                    "to": "hxb0776ee37f5b45bfaea8cff1d8232fbb6122ec32",
                    "value": "100",
                    "stepLimit": "12345",
                    "timestamp": "5500598",
                    "nonce": "7362",
                    "signature": "VAia7YZ2Ji6igKWzjR2YsGa2m53nKPrfK7uXYW78QLE+ATehAVZPC40szvAiA6NEU5gCYB4c4qaQzqDh2ugcHgA=",
                    "dataType": "call",
                    "data": {
                        "method": "transfer",
                        "params": {
                            "from": "hxbe258ceb872e08851f1f59694dac2558708ece11",
                            "to": "hxf5aac6e693ec2cb5973d3f314334670b3f85ad14",
                            "value": "56bc75e2d63100000"
                        }
                    }
                }
            }]
        }

        answer = {
            "block": {
                "blockHeight": "0x3e8",
                "blockHash": "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
                "timestamp": "0x499602d2",
                "prevBlockHash": "b7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
            },
            "transactions": [{
                "method": "icx_sendTransaction",
                "params": {
                    "version": "0x3",
                    "from": "hxbe258ceb872e08851f1f59694dac2558708ece11",
                    "to": "hxb0776ee37f5b45bfaea8cff1d8232fbb6122ec32",
                    "value": "0x100",
                    "stepLimit": "0x3039",
                    "timestamp": "0x53eeb6",
                    "nonce": "0x1cc2",
                    "signature": "VAia7YZ2Ji6igKWzjR2YsGa2m53nKPrfK7uXYW78QLE+ATehAVZPC40szvAiA6NEU5gCYB4c4qaQzqDh2ugcHgA=",
                    "dataType": "call",
                    "data": {
                        "method": "transfer",
                        "params": {
                            "from": "hxbe258ceb872e08851f1f59694dac2558708ece11",
                            "to": "hxf5aac6e693ec2cb5973d3f314334670b3f85ad14",
                            "value": "56bc75e2d63100000"
                        }
                    }
                }
            }]
        }

        result = convert_params(question, ParamType.invoke)
        logging.info(f"result : {json.dumps(result, indent=4)}")
        self.assertEqual(result, answer)

    def test_get_tx_by_hash_response(self):
        question = {
            "txHash": "00abcdef1234567890",
            "blockHeight": "1234",
            "blockHash": "00abcdef0981"
        }

        answer = {
            "txHash": "0x00abcdef1234567890",
            "blockHeight": "0x4d2",
            "blockHash": "0x00abcdef0981"
        }

        result = convert_params(question, ParamType.get_tx_by_hash_response)
        logging.info(f"result : {json.dumps(result, indent=4)}")
        self.assertEqual(result, answer)

    def test_get_block_response(self):
        question = {
            "prev_block_hash": "0x012332abcde",
            "merkle_tree_root_hash": "0x01234abc96",
            "time_stamp": "0x1cc3169d2c",
            "block_hash": "0x01282384583bb",
            "height": 124,
            "confirmed_transaction_list": [
                {
                    "from": "hx120983102983",
                    "to": "hx109238019238",
                    "txHash": "0123213b1a"
                },
                {
                    "from": "hx12098310293",
                    "to": "hx10923801928",
                    "txHash": "0123213b1a"
                },
                {
                    "from": "hx12093102983",
                    "to": "hx10923809238",
                    "txHash": "0123213b1a"
                },
                {
                    "from": "hx1209831029823",
                    "to": "hx1092380192382",
                    "txHash": "0123213b1a"
                }
            ]
        }

        answer = {
            "prev_block_hash": "0x012332abcde",
            "merkle_tree_root_hash": "0x01234abc96",
            "time_stamp": "0x1cc3169d2c",
            "block_hash": "0x01282384583bb",
            "height": 124,
            "confirmed_transaction_list": [
                {
                    "from": "hx120983102983",
                    "to": "hx109238019238",
                    "txHash": "0x0123213b1a"
                },
                {
                    "from": "hx12098310293",
                    "to": "hx10923801928",
                    "txHash": "0x0123213b1a"
                },
                {
                    "from": "hx12093102983",
                    "to": "hx10923809238",
                    "txHash": "0x0123213b1a"
                },
                {
                    "from": "hx1209831029823",
                    "to": "hx1092380192382",
                    "txHash": "0x0123213b1a"
                }
            ]
        }

        result = convert_params(question, ParamType.get_block_response)
        logging.info(f"result : {json.dumps(result, indent=4)}")
        self.assertEqual(result, answer)

    def test_send_tx_response(self):
        question = "234234"
        answer = "0x234234"
        result = convert_params(question, ParamType.send_tx_response)
        logging.info(f"result : {json.dumps(result, indent=4)}")
        self.assertEqual(result, answer)

        question = "0x234234"
        answer = "0x234234"
        result = convert_params(question, ParamType.send_tx_response)
        logging.info(f"result : {json.dumps(result, indent=4)}")
        self.assertEqual(result, answer)

        question = 234234
        answer = "0x392fa"
        result = convert_params(question, ParamType.send_tx_response)
        logging.info(f"result : {json.dumps(result, indent=4)}")
        self.assertEqual(result, answer)

        question = "qsaad"
        answer = ValueError
        try:
            convert_params(question, ParamType.send_tx_response)
        except BaseException as e:
            self.assertEqual(answer, type(e))
