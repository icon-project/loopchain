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

from loopchain import configure as conf
from loopchain import utils
from loopchain.baseservice import ObjectManager, TimerService, Timer
from loopchain.blockchain.blocks import BlockSerializer, BlockVerifier
from loopchain.channel.channel_property import ChannelProperty
from loopchain.protos import message_code

config.log_requests = False
config.log_responses = False
ws_methods = AsyncMethods()
CONNECTION_FAIL_CONDITIONS = {message_code.Response.fail_subscribe_limit,
                              message_code.Response.fail_connection_closed}


class NodeSubscriber:
    def __init__(self, channel, rs_target):
        self.__channel = channel
        self.__rs_target = rs_target
        self.__target_uri = f"{'wss' if conf.SUBSCRIBE_USE_HTTPS else 'ws'}://{self.__rs_target}/api/ws/{channel}"
        self.__exception = None
        self.__websocket = None
        self.__subscribe_event: Event = None

        ws_methods.add(self.node_ws_PublishHeartbeat)
        ws_methods.add(self.node_ws_PublishNewBlock)

        logging.debug(f"websocket target uri : {self.__target_uri}")

    def __del__(self):
        if self.__websocket is not None:
            utils.logger.warning(f"Have to close before delete NodeSubscriber instance({self})")

    async def close(self):
        if self.__websocket is not None:
            await self.__websocket.close()
            self.__websocket = None

    async def subscribe(self, block_height, event: Event):
        self.__exception = None
        self.__subscribe_event = event

        try:
            # set websocket payload maxsize to 4MB.
            self.__websocket = await websockets.connect(self.__target_uri, max_size=4 * conf.MAX_TX_SIZE_IN_BLOCK)
            logging.debug(f"Websocket connection is Completed.")
            request = Request("node_ws_Subscribe", height=block_height, peer_id=ChannelProperty().peer_id)
            await self.__websocket.send(json.dumps(request))
            await self.__subscribe_loop(self.__websocket)
        except Exception as e:
            traceback.print_exc()
            logging.error(f"websocket subscribe exception, caused by: {type(e)}, {e}")
            raise ConnectionError
        finally:
            await self.close()

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

    async def node_ws_PublishNewBlock(self, **kwargs):
        if 'error' in kwargs:
            if kwargs.get('code') in CONNECTION_FAIL_CONDITIONS:
                self.__exception = ConnectionError(kwargs['error'])
                return
            else:
                return ObjectManager().channel_service.shutdown_peer(message=kwargs.get('error'))

        block_dict, confirm_info_str = kwargs.get('block'), kwargs.get('confirm_info')
        confirm_info = confirm_info_str.encode("utf-8") if confirm_info_str else None
        blockchain = ObjectManager().channel_service.block_manager.get_blockchain()

        new_block_height = blockchain.block_versioner.get_height(block_dict)
        if new_block_height > blockchain.block_height:
            block_version = blockchain.block_versioner.get_version(new_block_height)
            block_serializer = BlockSerializer.new(block_version, blockchain.tx_versioner)
            confirmed_block = block_serializer.deserialize(block_dict)

            block_verifier = BlockVerifier.new(block_version, blockchain.tx_versioner)
            block_verifier.invoke_func = ObjectManager().channel_service.score_invoke
            reps = ObjectManager().channel_service.get_rep_ids()
            block_verifier.verify(confirmed_block,
                                  blockchain.last_block,
                                  blockchain,
                                  blockchain.last_block.header.next_leader,
                                  reps=reps)

            logging.debug(f"add_confirmed_block height({confirmed_block.header.height}), "
                          f"hash({confirmed_block.header.hash.hex()}), confirm_info({confirm_info})")

            ObjectManager().channel_service.block_manager.add_confirmed_block(confirmed_block=confirmed_block,
                                                                              confirm_info=confirm_info)

    async def node_ws_PublishHeartbeat(self, **kwargs):
        def _callback(exception):
            self.__exception = exception

        if 'error' in kwargs:
            _callback(ConnectionError(kwargs['error']))
            return

        if not self.__subscribe_event.is_set():
            self.__subscribe_event.set()
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
