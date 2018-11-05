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
"""State Machine for Channel Service"""
from earlgrey import MessageQueueService
from transitions import State

import loopchain.utils as util
from loopchain.protos import loopchain_pb2
from loopchain.statemachine import statemachine


@statemachine.StateMachine("Channel State Machine")
class ChannelStateMachine(object):
    states = ['InitComponents',
              State(name='Consensus', on_enter='_consensus_on_enter'),
              State(name='BlockHeightSync', on_enter='_blockheightsync_on_enter'),
              'EvaluateNetwork', 'BlockSync', 'SubscribeNetwork',
              State(name='Vote', on_enter='_vote_on_enter', on_exit='_vote_on_exit'),
              State(name='BlockGenerate', on_enter='_blockgenerate_on_enter', on_exit='_blockgenerate_on_exit'),
              'LeaderComplain',
              'GracefulShutdown']
    init_state = 'InitComponents'
    state = init_state

    def __init__(self, channel_service):
        self.__channel_service = channel_service

        self.machine.add_transition('complete_sync', 'SubscribeNetwork', 'BlockGenerate', conditions=['_is_leader'])
        self.machine.add_transition('complete_sync', 'SubscribeNetwork', 'Vote')

    @statemachine.transition(source='InitComponents', dest='Consensus')
    def complete_init_components(self):
        pass

    @statemachine.transition(source='Consensus', dest='BlockHeightSync')
    def block_height_sync(self):
        pass

    @statemachine.transition(source='BlockHeightSync',
                             dest='EvaluateNetwork',
                             after='_do_evaluate_network')
    def evaluate_network(self):
        pass

    @statemachine.transition(source=('EvaluateNetwork', 'Vote'),
                             dest='BlockSync',
                             after='_do_block_sync')
    def block_sync(self):
        pass

    @statemachine.transition(source=('BlockSync', 'EvaluateNetwork'),
                             dest='SubscribeNetwork',
                             after='_do_subscribe_network')
    def subscribe_network(self):
        pass

    @statemachine.transition(source='Vote', dest='Vote', after='_do_vote')
    def vote(self):
        pass

    def complete_sync(self):
        pass

    def _is_leader(self):
        return self.__channel_service.block_manager.peer_type == loopchain_pb2.BLOCK_GENERATOR

    def _consensus_on_enter(self):
        # util.logger.spam(f"\nenter_block_height_sync")
        self.block_height_sync()

    def _blockheightsync_on_enter(self):
        # util.logger.spam(f"\nenter_block_sync")
        self.evaluate_network()

    def _enter_block_sync(self):
        # util.logger.spam(f"\nenter_block_sync")
        self.block_sync()

    def _do_block_sync(self):
        # util.logger.spam(f"\ndo_block_sync")
        loop = MessageQueueService.loop
        loop.create_task(self.__channel_service.block_height_sync_channel())

    def _do_evaluate_network(self):
        # util.logger.spam(f"\ndo_evaluate_network")
        loop = MessageQueueService.loop
        loop.create_task(self.__channel_service.evaluate_network())

    def _do_subscribe_network(self):
        # util.logger.spam(f"\ndo_subscribe_network")
        loop = MessageQueueService.loop
        loop.create_task(self.__channel_service.subscribe_network())

    def _do_vote(self):
        # util.logger.spam(f"\ndo_vote")
        self.__channel_service.block_manager.vote_as_peer()

    def _vote_on_enter(self):
        util.logger.spam(f"\nvote_on_enter")

    def _vote_on_exit(self):
        util.logger.spam(f"\nvote_on_exit")

    def _blockgenerate_on_enter(self):
        # util.logger.spam(f"\nblockgenerate_on_enter")
        self.__channel_service.block_manager.start_block_generate_timer()

    def _blockgenerate_on_exit(self):
        # util.logger.spam(f"\nblockgenerate_on_exit")
        self.__channel_service.block_manager.stop_block_generate_timer()
