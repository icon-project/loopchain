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

import asyncio
import logging
import unittest
import multiprocessing
import test_util

from pika.exceptions import ChannelClosed
from earlgrey import MessageQueueStub, MessageQueueService, MessageQueueType, message_queue_task
from loopchain import configure as conf
from loopchain.channel.channel_inner_service import ChannelInnerService, ChannelInnerStub
from loopchain.peer import PeerInnerService, PeerInnerStub
from loopchain.scoreservice.score_inner_service import ScoreInnerService, ScoreInnerStub
from loopchain.utils import loggers
from loopchain.utils.message_queue import StubCollection


loggers.set_preset_type(loggers.PresetType.develop)
loggers.update_preset()


class TestMessageQueue(unittest.TestCase):
    def setUp(self):
        test_util.print_testname(self._testMethodName)

    def test_basic(self):
        class Task:
            @message_queue_task
            async def sum(self, x, y):
                return x + y

            @message_queue_task
            def multiply(self, x, y):
                return x * y

            @message_queue_task(type_=MessageQueueType.Worker)
            def ping(self, value):
                logging.info(f'value : {value}')
                assert value == 123

            @message_queue_task(type_=MessageQueueType.Worker)
            async def stop(self):
                logging.info(f'stop')
                asyncio.get_event_loop().stop()

        class Stub(MessageQueueStub[Task]):
            TaskType = Task

        class Service(MessageQueueService[Task]):
            TaskType = Task

        route_key = 'something same you want'

        def _run_server():
            async def _run():
                message_queue_service = Service(conf.AMQP_TARGET, route_key)
                await message_queue_service.connect()

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            loop.create_task(_run())
            loop.run_forever()

        def _run_client():
            async def _run():
                message_queue_stub = Stub(conf.AMQP_TARGET, route_key)
                await message_queue_stub.connect()

                result = await message_queue_stub.async_task().sum(10, 20)
                self.assertEqual(result, 30)

                result = message_queue_stub.sync_task().multiply(10, 20)
                self.assertEqual(result, 200)

                message_queue_stub.sync_task().ping(123)

                await message_queue_stub.async_task().stop()

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            loop.run_until_complete(_run())

        server = multiprocessing.Process(target=_run_server)
        server.daemon = True
        server.start()

        client = multiprocessing.Process(target=_run_client)
        client.daemon = True
        client.start()

        server.join()
        client.join()

    def test_peer_task(self):
        async def _run():
            route_key = conf.PEER_QUEUE_NAME_FORMAT.format(amqp_key=conf.AMQP_KEY)

            service = PeerInnerService(conf.AMQP_TARGET, route_key, peer_service=None)
            stub = PeerInnerStub(conf.AMQP_TARGET, route_key)

            await service.connect(exclusive=True)
            await stub.connect()

            result = await stub.async_task().hello()
            self.assertEqual(result, 'peer_hello')

            bad_service = PeerInnerService(conf.AMQP_TARGET, route_key, peer_service=None)
            try:
                await bad_service.connect()
                raise RuntimeError('Peer inner service is not exclusive.')
            except ChannelClosed:
                pass

            try:
                await bad_service.connect(exclusive=True)
                raise RuntimeError('Peer inner service is not exclusive.')
            except ChannelClosed:
                pass

        try:
            loop = asyncio.get_event_loop()
            loop.run_until_complete(_run())
        except:
            pass

    def test_channel_task(self):
        async def _run():
            route_key = conf.CHANNEL_QUEUE_NAME_FORMAT.format(
                channel_name=conf.LOOPCHAIN_DEFAULT_CHANNEL, amqp_key=conf.AMQP_KEY)

            service = ChannelInnerService(conf.AMQP_TARGET, route_key, channel_service=None)
            stub = ChannelInnerStub(conf.AMQP_TARGET, route_key)

            await service.connect(exclusive=True)
            await stub.connect()

            result = await stub.async_task().hello()
            self.assertEqual(result, 'channel_hello')

            bad_service = ChannelInnerService(conf.AMQP_TARGET, route_key, channel_service=None)
            try:
                await bad_service.connect()
                raise RuntimeError('Channel inner service is not exclusive.')
            except ChannelClosed:
                pass

            try:
                await bad_service.connect(exclusive=True)
                raise RuntimeError('Channel inner service is not exclusive.')
            except ChannelClosed:
                pass

        try:
            loop = asyncio.get_event_loop()
            loop.run_until_complete(_run())
        except:
            pass

    def test_score_task(self):
        route_key = conf.SCORE_QUEUE_NAME_FORMAT.format(
            score_package_name=conf.DEFAULT_SCORE_PACKAGE,
            channel_name=conf.LOOPCHAIN_DEFAULT_CHANNEL,
            amqp_key=conf.AMQP_KEY)

        service = ScoreInnerService(conf.AMQP_TARGET, route_key, score_service=None)
        stub = ScoreInnerStub(conf.AMQP_TARGET, route_key)

        async def _run():
            await service.connect(exclusive=True)
            await stub.connect()

            result = await stub.async_task().hello()
            self.assertEqual(result, 'score_hello')

            bad_service = ScoreInnerService(conf.AMQP_TARGET, route_key, score_service=None)
            try:
                await bad_service.connect()
                raise RuntimeError('Score inner service is not exclusive.')
            except ChannelClosed:
                pass

            try:
                await bad_service.connect(exclusive=True)
                raise RuntimeError('Score inner service is not exclusive.')
            except ChannelClosed:
                pass

        try:
            loop = asyncio.get_event_loop()
            loop.run_until_complete(_run())
        except:
            pass

    def test_stub_collection(self):
        async def _run():
            route_key = conf.PEER_QUEUE_NAME_FORMAT.format(amqp_key=conf.AMQP_KEY)
            peer_inner_service = PeerInnerService(conf.AMQP_TARGET, route_key, peer_service=None)
            await peer_inner_service.connect()

            route_key = conf.CHANNEL_QUEUE_NAME_FORMAT.format(
                channel_name=conf.LOOPCHAIN_DEFAULT_CHANNEL, amqp_key=conf.AMQP_KEY)
            channel_inner_service = ChannelInnerService(conf.AMQP_TARGET, route_key, channel_service=None)
            await channel_inner_service.connect()

            route_key = conf.SCORE_QUEUE_NAME_FORMAT.format(
                score_package_name=conf.DEFAULT_SCORE_PACKAGE,
                channel_name=conf.LOOPCHAIN_DEFAULT_CHANNEL,
                amqp_key=conf.AMQP_KEY)
            score_inner_service = ScoreInnerService(conf.AMQP_TARGET, route_key, score_service=None)
            await score_inner_service.connect()

            StubCollection().amqp_target = conf.AMQP_TARGET
            StubCollection().amqp_key = conf.AMQP_KEY

            await StubCollection().create_peer_stub()
            result = await StubCollection().peer_stub.async_task().hello()
            self.assertEqual(result, 'peer_hello')

            await StubCollection().create_channel_stub(conf.LOOPCHAIN_DEFAULT_CHANNEL)
            result = await StubCollection().channel_stubs[conf.LOOPCHAIN_DEFAULT_CHANNEL].async_task().hello()
            self.assertEqual(result, 'channel_hello')

            await StubCollection().create_score_stub(conf.LOOPCHAIN_DEFAULT_CHANNEL, conf.DEFAULT_SCORE_PACKAGE)
            result = await StubCollection().score_stubs[conf.LOOPCHAIN_DEFAULT_CHANNEL].async_task().hello()
            self.assertEqual(result, 'score_hello')

        try:
            loop = asyncio.get_event_loop()
            loop.run_until_complete(_run())
        except:
            pass
