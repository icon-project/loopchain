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
"""Test Channel Manager for new functions not duplicated another tests"""
import asyncio
import logging
import unittest

import os

import loopchain.utils as util
import testcase.unittest.test_util as test_util
from loopchain import configure as conf
from loopchain.baseservice import StubManager
from loopchain.channel.channel_service import ChannelService, ChannelProperty
from loopchain.protos import message_code
from loopchain.utils import loggers

loggers.set_preset_type(loggers.PresetType.develop)
loggers.update_preset()


class TestChannelService(unittest.TestCase):

    __channel_service = None

    def setUp(self):
        test_util.print_testname(self._testMethodName)

    def tearDown(self):
        self.__channel_service.cleanup()
        conf.DEFAULT_SCORE_REPOSITORY_PATH = os.path.join(conf.LOOPCHAIN_ROOT_PATH, 'score')

    def test_load_score_containers(self):
        """GIVEN default_score_package, and test_score_package different value,
        conf.PORT_DIFF_TEST_SCORE_CONTAINER, new ChannelManager, peer_port for channel manager
        WHEN ChannelManager.load_score_containers
        THEN score_info, stub_to_score_container, score_process
        """
        # GIVEN
        amqp_target = conf.AMQP_TARGET

        conf.DEFAULT_SCORE_REPOSITORY_PATH = os.path.join(conf.LOOPCHAIN_ROOT_PATH, 'resources/test_score_repository')
        default_score_package = 'loopchain/default'

        peer_port = 7100

        # WHEN
        async def init_channel_service():
            self.__channel_service = ChannelService(
                conf.LOOPCHAIN_DEFAULT_CHANNEL, amqp_target, conf.AMQP_KEY)
            ChannelProperty().peer_target = f"{util.get_private_ip()}:{peer_port}"
            ChannelProperty().score_package = default_score_package

            await self.__channel_service._ChannelService__init_score_container()

        loop = asyncio.get_event_loop()
        loop.run_until_complete(init_channel_service())

        # THEN
        # stub port must setting port

        # score_info
        default_score_info: dict = self.__channel_service.score_info

        logging.debug(f'default_score_info : {default_score_info}')

        self.assertEqual(default_score_info[message_code.MetaParams.ScoreInfo.score_id], default_score_package)


if __name__ == '__main__':
    unittest.main()
