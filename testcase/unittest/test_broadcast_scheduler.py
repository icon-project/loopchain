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
"""Test Broadcast Process"""

import logging
import time
import unittest

from loopchain.baseservice import BroadcastScheduler
from loopchain.utils import loggers


loggers.set_preset_type(loggers.PresetType.develop)
loggers.update_preset()


class TestBroadcastScheduler(unittest.TestCase):

    def test_broadcast_process(self):
        ## GIVEN
        broadcast_scheduler = BroadcastScheduler()
        broadcast_scheduler.start()

        ## WHEN
        times = 0
        while times < 2:
            future = broadcast_scheduler.schedule_job("status", "param")
            print(f'broadcast_process status : {future.result()}')

            time.sleep(1)
            times += 1

        broadcast_scheduler.stop()
        broadcast_scheduler.wait()

        ## THEN
        # self.assertEqual(result, message_code.get_response_msg(message_code.Response.success))


if __name__ == '__main__':
    unittest.main()
