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
from loopchain.statemachine import statemachine


@statemachine.StateMachine("Channel State Machine")
class ChannelStateMachine(object):
    states = ['InitComponents', 'Consensus', 'BlockHeightSync',
              'BlockSync', 'EvaluateNetwork',
              'Vote', 'BlockGenerate', 'LeaderComplain',
              'GracefulShutdown']
    init_state = 'InitComponents'

    def __init__(self):
        pass

    @statemachine.transition
    def complete_init_components(self, source='InitComponents', dest='Consensus', after='do_block_height_sync'):
        pass

    @statemachine.transition
    def block_height_sync(self, source='Consensus', dest='BlockHeightSync', after='do_block_sync'):
        pass

    @statemachine.transition
    def block_sync(self, source='BlockHeightSync', dest='BlockSync'):
        pass

    def do_block_height_sync(self):
        # util.logger.spam(f"\ndo_block_height_sync")
        self.block_height_sync()

    def do_block_sync(self):
        # util.logger.spam(f"do_block_sync")
        self.block_sync()
