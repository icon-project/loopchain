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
"""Test Radiostation Admin Manager"""
import unittest
import json

import os

from loopchain.radiostation import AdminManager
from loopchain import configure as conf
from loopchain.utils import loggers

loggers.set_preset_type(loggers.PresetType.develop)
loggers.update_preset()


class TestRSAdminManager(unittest.TestCase):

    def test_get_channel_info_by_peer_target(self):
        # GIVEN
        default_CHANNEL_MANAGE_DATA_PATH = conf.CHANNEL_MANAGE_DATA_PATH
        conf.CHANNEL_MANAGE_DATA_PATH = os.path.join(conf.LOOPCHAIN_ROOT_PATH,
                                                     "testcase/unittest/channel_manage_data_for_test.json")
        admin_manager = AdminManager("station")
        peer_target1 = '1.1.1.1:1111'
        peer_target2 = '2.2.2.2:2222'
        peer_target3 = '3.3.3.3:3333'
        peer_target4 = '4.4.4.4:4444'

        channel1 = 'loopchain_default'
        channel2 = 'loopchain_test'

        # WHEN
        channel_infos1 = json.loads(admin_manager.get_channel_infos_by_peer_target(peer_target1))
        channel_infos2 = json.loads(admin_manager.get_channel_infos_by_peer_target(peer_target2))
        channel_infos3 = json.loads(admin_manager.get_channel_infos_by_peer_target(peer_target3))
        channel_infos4 = json.loads(admin_manager.get_channel_infos_by_peer_target(peer_target4))

        # THEN
        self.assertEqual(list(channel_infos1.keys()), [channel1, channel2])
        self.assertEqual(list(channel_infos2.keys()), [channel1])
        self.assertEqual(list(channel_infos3.keys()), [channel2])
        self.assertEqual(list(channel_infos4.keys()), [])

        # CLEAR
        conf.CHANNEL_MANAGE_DATA_PATH = default_CHANNEL_MANAGE_DATA_PATH

    def test_get_all_channel_info(self):
        # GIVEN
        default_CHANNEL_MANAGE_DATA_PATH = conf.CHANNEL_MANAGE_DATA_PATH
        conf.CHANNEL_MANAGE_DATA_PATH = os.path.join(conf.LOOPCHAIN_ROOT_PATH,
                                                     "testcase/unittest/channel_manage_data_for_test.json")
        # WHEN
        all_channel_info = AdminManager("station").get_all_channel_info()

        # THEN
        self.assertTrue(isinstance(all_channel_info, str))

        # CLEAR
        conf.CHANNEL_MANAGE_DATA_PATH = default_CHANNEL_MANAGE_DATA_PATH

    def test_add_peer_target(self):
        # GIVEN
        default_CHANNEL_MANAGE_DATA_PATH = conf.CHANNEL_MANAGE_DATA_PATH
        conf.CHANNEL_MANAGE_DATA_PATH = os.path.join(conf.LOOPCHAIN_ROOT_PATH,
                                                     "testcase/unittest/channel_manage_data_for_test.json")
        admin_manager = AdminManager("station")
        i = 0
        new_peer_target = '9.9.9.9:9999'
        loaded_data = admin_manager.json_data
        channel_list = list(loaded_data)
        peer_target_list = loaded_data[channel_list[0]]["peers"]

        # WHEN
        modified_data = admin_manager.add_peer_target(
            loaded_data, channel_list, new_peer_target, peer_target_list, i)
        second_peer_target_list = modified_data[channel_list[0]]["peers"]

        # THEN
        self.assertEqual(len(second_peer_target_list), 3)

        # CLEAR
        conf.CHANNEL_MANAGE_DATA_PATH = default_CHANNEL_MANAGE_DATA_PATH

    def test_delete_peer_target(self):
        # GIVEN
        default_CHANNEL_MANAGE_DATA_PATH = conf.CHANNEL_MANAGE_DATA_PATH
        conf.CHANNEL_MANAGE_DATA_PATH = os.path.join(conf.LOOPCHAIN_ROOT_PATH,
                                                     "testcase/unittest/channel_manage_data_for_test.json")
        admin_manager = AdminManager("station")
        i = 0
        remove_peer_target = '2.2.2.2:2222'
        loaded_data = admin_manager.json_data
        filtered_channel_infos = admin_manager.get_channel_infos_by_peer_target(remove_peer_target)
        filtered_list = list(json.loads(filtered_channel_infos))

        # WHEN
        modified_data = admin_manager.delete_peer_target(
            loaded_data, remove_peer_target, filtered_list, i)
        second_peer_target_list = modified_data[filtered_list[0]]["peers"]

        # THEN
        self.assertEqual(len(second_peer_target_list), 1)

        # CLEAR
        conf.CHANNEL_MANAGE_DATA_PATH = default_CHANNEL_MANAGE_DATA_PATH


if __name__ == '__main__':
    unittest.main()
