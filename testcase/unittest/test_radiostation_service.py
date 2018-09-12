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
"""Test RadioStation Service"""
import unittest

from loopchain import configure as conf
from loopchain.radiostation import RadioStationService
from loopchain.utils import loggers

loggers.set_preset_type(loggers.PresetType.develop)
loggers.update_preset()


class TestRadioStationService(unittest.TestCase):

    @unittest.skip("After Random Table Multi channelize ")
    def test_random_generate(self):
        """GIVEN Random Seed and conf.RANDOM_NUM, conf.KMS = True
        WHEN 2 RadioStationService init params seed
        THEN RadioStationService.__random_table size is conf.RANDOM_TABLE_SIZE
        and each RadioStationService has same random table
        """

        # GIVEN
        seed = 123456

        conf.KEY_LOAD_TYPE = conf.KeyLoadType.RANDOM_TABLE_DERIVATION

        # WHEN THEN
        random_table = TestRadioStationService.create_rand_table(seed)
        random_table2 = TestRadioStationService.create_rand_table(seed)

        self.assertEqual(len(random_table), conf.RANDOM_TABLE_SIZE)

        for i in range(len(random_table)):
            random_data: int = random_table[i]
            self.assertEqual(random_data, random_table2[i])

        conf.KEY_LOAD_TYPE = conf.KeyLoadType.FILE_LOAD

    @staticmethod
    def create_rand_table(seed) -> list:
        # WHEN
        rs_service = RadioStationService(rand_seed=seed)
        return rs_service._RadioStationService__random_table


if __name__ == '__main__':
    unittest.main()
