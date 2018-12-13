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

from loopchain import configure as conf
from loopchain.baseservice import ObjectManager
from loopchain.blockchain import BlockSerializer


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
                logging.debug(f"Websocket connection is Completed.")
                event.set()
                request = json.dumps({
                    'height': block_height
                })
                await websocket.send(request)
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

            if 'error' in response_dict:
                return ObjectManager().channel_service.shutdown_peer(message=response_dict.get('error'))

            new_block_height = response_dict.get('height')
            if new_block_height > ObjectManager().channel_service.block_manager.get_blockchain().block_height:
                await self.__add_confirmed_block(block_json=response)

    async def __add_confirmed_block(self, block_json: str):
        block_dict = json.loads(block_json)
        blockchain = ObjectManager().channel_service.block_manager.get_blockchain()

        block_height = blockchain.block_versioner.get_version(block_dict)
        block_version = blockchain.block_versioner.get_version(block_height)
        block_serializer = BlockSerializer.new(block_version, blockchain.tx_versioner)
        confirmed_block = block_serializer.deserialize(block_dict)

        logging.debug(f"add_confirmed_block height({confirmed_block.header.height}), "
                      f"hash({confirmed_block.header.hash.hex()})")

        ObjectManager().channel_service.block_manager.add_confirmed_block(confirmed_block)
