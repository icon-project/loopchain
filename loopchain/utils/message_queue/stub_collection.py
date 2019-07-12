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

import logging
from typing import Dict, TYPE_CHECKING

from loopchain.components import SingletonMetaClass

if TYPE_CHECKING:
    from loopchain.peer import PeerInnerStub
    from loopchain.channel.channel_inner_service import (ChannelInnerStub,
                                                         ChannelTxCreatorInnerStub,
                                                         ChannelTxReceiverInnerStub)
    from loopchain.scoreservice import IconScoreInnerStub


class StubCollection(metaclass=SingletonMetaClass):
    """
    rpc stubs with rabbitmq for inter process communication

    FIXME : consider singleton to borg
    ref : https://github.com/faif/python-patterns/blob/master/patterns/creational/borg.py
    """

    def __init__(self):
        self.amqp_target = None
        self.amqp_key = None

        self.peer_stub: PeerInnerStub = None
        self.channel_stubs: Dict[str, ChannelInnerStub] = {}
        self.channel_tx_creator_stubs: Dict[str, ChannelTxCreatorInnerStub] = {}
        self.channel_tx_receiver_stubs: Dict[str, ChannelTxReceiverInnerStub] = {}
        self.icon_score_stubs: Dict[str, IconScoreInnerStub] = {}

    async def create_peer_stub(self):
        from loopchain import configure as conf
        from loopchain.peer import PeerInnerStub

        queue_name = conf.PEER_QUEUE_NAME_FORMAT.format(amqp_key=self.amqp_key)
        self.peer_stub = PeerInnerStub(self.amqp_target, queue_name, conf.AMQP_USERNAME, conf.AMQP_PASSWORD)
        await self.peer_stub.connect(conf.AMQP_CONNECTION_ATTEMPTS, conf.AMQP_RETRY_DELAY)
        return self.peer_stub

    async def create_channel_stub(self, channel_name):
        from loopchain import configure as conf
        from loopchain.channel.channel_inner_service import ChannelInnerStub

        queue_name = conf.CHANNEL_QUEUE_NAME_FORMAT.format(
            channel_name=channel_name, amqp_key=self.amqp_key)
        stub = ChannelInnerStub(self.amqp_target, queue_name, conf.AMQP_USERNAME, conf.AMQP_PASSWORD)
        await stub.connect(conf.AMQP_CONNECTION_ATTEMPTS, conf.AMQP_RETRY_DELAY)
        self.channel_stubs[channel_name] = stub

        logging.debug(f"ChannelTasks : {channel_name}, Queue : {queue_name}")
        return stub

    async def create_channel_tx_creator_stub(self, channel_name):
        from loopchain import configure as conf
        from loopchain.channel.channel_inner_service import ChannelTxCreatorInnerStub

        queue_name = conf.CHANNEL_TX_CREATOR_QUEUE_NAME_FORMAT.format(channel_name=channel_name, amqp_key=self.amqp_key)
        stub = ChannelTxCreatorInnerStub(self.amqp_target, queue_name)
        await stub.connect()
        self.channel_tx_creator_stubs[channel_name] = stub

        logging.debug(f"ChannelTxCreatorTasks : {channel_name}, Queue : {queue_name}")
        return stub

    async def create_channel_tx_receiver_stub(self, channel_name):
        from loopchain import configure as conf
        from loopchain.channel.channel_inner_service import ChannelTxReceiverInnerStub

        queue_name = conf.CHANNEL_TX_RECEIVER_QUEUE_NAME_FORMAT.format(
            channel_name=channel_name, amqp_key=self.amqp_key)
        stub = ChannelTxReceiverInnerStub(self.amqp_target, queue_name, conf.AMQP_USERNAME, conf.AMQP_PASSWORD)
        await stub.connect(conf.AMQP_CONNECTION_ATTEMPTS, conf.AMQP_RETRY_DELAY)
        self.channel_tx_receiver_stubs[channel_name] = stub

        logging.debug(f"ChannelTxReceiverTasks : {channel_name}, Queue : {queue_name}")
        return stub

    async def create_icon_score_stub(self, channel_name):
        from loopchain import configure as conf
        from loopchain.scoreservice import IconScoreInnerStub

        queue_name = conf.ICON_SCORE_QUEUE_NAME_FORMAT.format(
            channel_name=channel_name, amqp_key=self.amqp_key
        )
        stub = IconScoreInnerStub(self.amqp_target, queue_name, conf.AMQP_USERNAME, conf.AMQP_PASSWORD)
        await stub.connect(conf.AMQP_CONNECTION_ATTEMPTS, conf.AMQP_RETRY_DELAY)
        self.icon_score_stubs[channel_name] = stub
        return stub
