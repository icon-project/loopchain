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
"""Class for websocket client between child(citizen) node and mother peer"""

import asyncio
import json
import logging

import websockets
from websockets.exceptions import InvalidStatusCode, InvalidMessage

from loopchain import configure as conf
from loopchain.baseservice import TimerService, Timer, ObjectManager
from loopchain.blockchain import Block


class NodeSubscriber:
    def __init__(self, channel, rs_target):
        self.__channel = channel
        self.__rs_target = rs_target
        self.__target_uri = f"{'wss' if conf.SUBSCRIBE_USE_HTTPS else 'ws'}://{self.__rs_target}/api/node/{channel}"

    @property
    def target_uri(self):
        return self.__target_uri

    async def subscribe(self, uri, block_height):
        while True:
            try:
                async with websockets.connect(uri) as websocket:
                    await self.__stop_shutdown_timer()
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
                logging.error(f"websocket subscribe exception, caused by: {type(e)}, {e}")
                await self.__start_shutdown_timer()
                await asyncio.sleep(conf.SUBSCRIBE_RETRY_TIMER)

    async def __subscribe_loop(self, websocket):
        while True:
            response = await websocket.recv()
            response_dict = json.loads(response)

            if 'error' in response_dict:
                return self.__shutdown_peer(message=response_dict.get('error'))

            new_block_height = response_dict.get('height')
            if new_block_height > ObjectManager().channel_service.block_manager.get_blockchain().block_height:
                await self.__add_confirmed_block(block_json=response)

    async def __start_shutdown_timer(self):
        timer_key = TimerService.TIMER_KEY_SHUTDOWN_WHEN_FAIL_SUBSCRIBE
        if timer_key not in ObjectManager().channel_service.timer_service.timer_list:
            error = f"Shutdown by Subscribe retry timeout({conf.SHUTDOWN_TIMER} sec)"
            ObjectManager().channel_service.timer_service.add_timer(
                timer_key,
                Timer(
                    target=timer_key,
                    duration=conf.SHUTDOWN_TIMER,
                    callback=self.__shutdown_peer,
                    callback_kwargs={"message": error}
                )
            )

    async def __stop_shutdown_timer(self):
        timer_key = TimerService.TIMER_KEY_SHUTDOWN_WHEN_FAIL_SUBSCRIBE
        if timer_key in ObjectManager().channel_service.timer_service.timer_list:
            ObjectManager().channel_service.timer_service.stop_timer(timer_key)

    async def __add_confirmed_block(self, block_json: str):
        block_dict = json.loads(block_json)
        confirmed_block = Block(channel_name=self.__channel)
        confirmed_block.deserialize_block(block_json.encode('utf-8'))
        confirmed_block.commit_state = block_dict.get('commit_state')

        logging.debug(f"add_confirmed_block height({confirmed_block.height}), "
                      f"hash({confirmed_block.block_hash})")
        ObjectManager().channel_service.block_manager.add_confirmed_block(confirmed_block)

    def __shutdown_peer(self, **kwargs):
        ObjectManager().channel_service.shutdown_peer(**kwargs)
