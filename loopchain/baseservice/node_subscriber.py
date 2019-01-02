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

import json
import logging
import traceback
from asyncio import Event

import websockets
from websockets.exceptions import InvalidStatusCode, InvalidMessage
from jsonrpcserver import config
from jsonrpcserver.aio import AsyncMethods
from jsonrpcclient.request import Request

from loopchain import configure as conf
from loopchain.baseservice import ObjectManager
from loopchain.blockchain import BlockSerializer
from loopchain.channel.channel_property import ChannelProperty


config.log_requests = False
config.log_responses = False
ws_methods = AsyncMethods()


class NodeSubscriber:
    def __init__(self, channel, rs_target):
        self.__channel = channel
        self.__rs_target = rs_target
        self.__target_uri = f"{'wss' if conf.SUBSCRIBE_USE_HTTPS else 'ws'}://{self.__rs_target}/api/node/{channel}"
        logging.debug(f"websocket target uri : {self.__target_uri}")

    @property
    def target_uri(self):
        return self.__target_uri

    async def subscribe(self, block_height, event: Event):
        try:
            # set websocket payload maxsize to 4MB.
            async with websockets.connect(self.__target_uri, max_size=4 * conf.MAX_TX_SIZE_IN_BLOCK) as websocket:
                event.set()

                logging.debug(f"Websocket connection is Completed.")
                request = Request("node_ws_Subscribe", height=block_height, peer_id=ChannelProperty().peer_id)
                await websocket.send(json.dumps(request))
                await self.__subscribe_loop(websocket)

        except (InvalidStatusCode, InvalidMessage) as e:
            logging.warning(f"websocket subscribe {type(e)} exception, caused by: {e}\n"
                            f"This target({self.__rs_target}) may not support websocket yet.")
            raise NotImplementedError
        except Exception as e:
            traceback.print_exc()
            logging.error(f"websocket subscribe exception, caused by: {type(e)}, {e}")
            raise ConnectionError

    async def __subscribe_loop(self, websocket):
        while True:
            response = await websocket.recv()
            response_dict = json.loads(response)

            await ws_methods.dispatch(response_dict)

    @staticmethod
    @ws_methods.add
    async def node_ws_PublishNewBlock(**kwargs):
        if 'error' in kwargs:
            return ObjectManager().channel_service.shutdown_peer(message=kwargs.get('error'))

        block_dict = kwargs.get('block')
        new_block_height = block_dict.get('height')
        if new_block_height > ObjectManager().channel_service.block_manager.get_blockchain().block_height:
            block_serializer = BlockSerializer.new(block_dict["version"])
            confirmed_block = block_serializer.deserialize(block_dict)

            logging.debug(f"add_confirmed_block height({confirmed_block.header.height}), "
                          f"hash({confirmed_block.header.hash.hex()})")

            ObjectManager().channel_service.block_manager.add_confirmed_block(confirmed_block)

    @staticmethod
    @ws_methods.add
    async def node_ws_PublishHeartbeat(**kwargs):
        if 'error' in kwargs:
            raise ConnectionError(kwargs['error'])

        logging.debug("websocket heartbeat.")
