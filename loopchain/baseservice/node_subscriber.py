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
"""Class for websocket client between child node and RS peer"""

import asyncio
import json
import logging
import traceback
from asyncio import Event

import websockets
from jsonrpcclient.request import Request
from jsonrpcserver import config
from jsonrpcserver.aio import AsyncMethods
from websockets.exceptions import InvalidStatusCode, InvalidMessage

from loopchain import configure as conf
from loopchain.baseservice import ObjectManager, TimerService, Timer
from loopchain.blockchain import BlockSerializer
from loopchain.channel.channel_property import ChannelProperty

config.log_requests = False
config.log_responses = False
ws_methods = AsyncMethods()


class NodeSubscriber:
    def __init__(self, channel, rs_target):
        self.__channel = channel
        self.__rs_target = rs_target
        self.__target_uri = f"{'wss' if conf.SUBSCRIBE_USE_HTTPS else 'ws'}://{self.__rs_target}/api/ws/{channel}"
        self.__exception = None
        self.__tried_with_old_uri = False

        ws_methods.add(self.node_ws_PublishHeartbeat)
        ws_methods.add(self.node_ws_PublishNewBlock)

        logging.debug(f"websocket target uri : {self.__target_uri}")

    async def subscribe(self, block_height, event: Event):
        self.__exception = None

        try:
            # set websocket payload maxsize to 4MB.
            async with websockets.connect(self.__target_uri, max_size=4 * conf.MAX_TX_SIZE_IN_BLOCK) as websocket:
                event.set()

                logging.debug(f"Websocket connection is Completed.")
                request = Request("node_ws_Subscribe", height=block_height, peer_id=ChannelProperty().peer_id)
                await websocket.send(json.dumps(request))
                await self.__subscribe_loop(websocket)
        except (InvalidStatusCode, InvalidMessage) as e:
            if not self.__tried_with_old_uri:
                await self.try_subscribe_to_old_uri(block_height, event)
                return
            logging.warning(f"websocket subscribe {type(e)} exception, caused by: {e}\n"
                            f"This target({self.__rs_target}) may not support websocket yet.")
            raise NotImplementedError
        except Exception as e:
            traceback.print_exc()
            logging.error(f"websocket subscribe exception, caused by: {type(e)}, {e}")
            raise ConnectionError

    async def __subscribe_loop(self, websocket):
        while True:
            if self.__exception:
                raise self.__exception

            try:
                response = await asyncio.wait_for(websocket.recv(), timeout=2 * conf.TIMEOUT_FOR_WS_HEARTBEAT)
            except asyncio.TimeoutError:
                continue
            else:
                response_dict = json.loads(response)
                await ws_methods.dispatch(response_dict)

    async def try_subscribe_to_old_uri(self, block_height, event: Event):
        self.__target_uri = self.__target_uri.replace('/ws', '/node')
        self.__tried_with_old_uri = True
        logging.info(f"try websocket again with old uri... old uri: {self.__target_uri}")
        await self.subscribe(block_height, event)

    async def node_ws_PublishNewBlock(self, **kwargs):
        if 'error' in kwargs:
            return ObjectManager().channel_service.shutdown_peer(message=kwargs.get('error'))

        block_dict = kwargs.get('block')
        blockchain = ObjectManager().channel_service.block_manager.get_blockchain()

        new_block_height = blockchain.block_versioner.get_height(block_dict)
        if new_block_height > blockchain.block_height:
            block_version = blockchain.block_versioner.get_version(new_block_height)
            block_serializer = BlockSerializer.new(block_version, blockchain.tx_versioner)
            confirmed_block = block_serializer.deserialize(block_dict)

            logging.debug(f"add_confirmed_block height({confirmed_block.header.height}), "
                          f"hash({confirmed_block.header.hash.hex()})")

            ObjectManager().channel_service.block_manager.add_confirmed_block(confirmed_block)

    async def node_ws_PublishHeartbeat(self, **kwargs):
        def _callback(exception):
            self.__exception = exception

        if 'error' in kwargs:
            _callback(ConnectionError(kwargs['error']))
            return

        timer_key = TimerService.TIMER_KEY_WS_HEARTBEAT
        timer_service = ObjectManager().channel_service.timer_service
        if timer_key in timer_service.timer_list:
            timer_service.reset_timer(timer_key)
        else:
            timer = Timer(
                target=timer_key,
                duration=3 * conf.TIMEOUT_FOR_WS_HEARTBEAT,
                callback=_callback,
                callback_kwargs={'exception': ConnectionError("No Heartbeat.")}
            )
            timer_service.add_timer(timer_key, timer)
