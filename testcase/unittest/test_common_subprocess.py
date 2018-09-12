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
"""Test Common Process"""

import logging
import time
import unittest

from loopchain.baseservice import CommonSubprocess
from loopchain.utils import loggers

loggers.set_preset_type(loggers.PresetType.develop)
loggers.update_preset()


class TestCommonSubprocess(unittest.TestCase):

    def test_common_subprocess(self):
        # GIVEN
        process_args = ['ls']
        logging.debug(f"run common subprocess....")
        subprocess = CommonSubprocess(process_args)
        logging.debug(f"after run common subprocess....")
        subprocess.start()
        subprocess.start()
        subprocess.start()
        self.assertTrue(subprocess.is_run())

        # WHEN
        time.sleep(2)
        subprocess.stop()
        subprocess.wait()
        subprocess.wait()
        subprocess.stop()

        # THEN
        self.assertFalse(subprocess.is_run())


if __name__ == '__main__':
    unittest.main()
