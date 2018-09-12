#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2018 ICON Foundation
#
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
"""Test Json Serialize"""

import json
import logging
import unittest

import testcase.unittest.test_util as test_util
from loopchain.blockchain import Transaction, TransactionStatus
from loopchain.utils import loggers

loggers.set_preset_type(loggers.PresetType.develop)
loggers.update_preset()


class CustomEncoder(json.JSONEncoder):
    def default(self, obj):
        if not hasattr(obj, '__dict__'):
            return None
        else:
            return obj.__dict__


def decode_object(obj):
    if '__Transaction__' in obj:
        tx = Transaction()
        tx.__dict__.update(obj['__Transaction__'])
        return tx
    return obj


class TestJsonSerialize(unittest.TestCase):

    def setUp(self):
        test_util.print_testname(self._testMethodName)

    def tearDown(self):
        pass

    def test_tx_json_serialize(self):
        # GIVEN
        tx = Transaction()
        tx.put_data("TEST")
        tx.transaction_type = TransactionStatus.confirmed
        logging.debug(f"transaction for test({tx})")

        # WHEN
        wrap_up = {"__Transaction__": tx}
        serialized = json.dumps(wrap_up, sort_keys=True, cls=CustomEncoder)
        logging.debug(f"serialized tx: {serialized}")

        tx_json = json.loads(serialized, object_hook=decode_object)
        logging.debug(f"deserialized tx: {tx_json}")

        wrap_up_again = {"__Transaction__": tx_json}
        serialized_again = json.dumps(wrap_up_again, sort_keys=True, cls=CustomEncoder)
        logging.debug(f"re-serialized tx: {serialized_again}")

        # THEN
        self.assertEqual(serialized, serialized_again)

    def text_tx_json_format(self):
        pass


if __name__ == '__main__':
    unittest.main()
