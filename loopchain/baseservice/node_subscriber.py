# Copyright 2019 ICON Foundation
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
"""Class for websocket client between child node and parent node"""

import asyncio
import json
import logging
from asyncio import Event
from urllib import parse

import websockets
from earlgrey import MessageQueueService
from jsonrpcclient.request import Request
from jsonrpcserver import config
from jsonrpcserver.aio import AsyncMethods
from websockets import WebSocketClientProtocol

from loopchain import configure as conf
from loopchain import utils
from loopchain.baseservice import ObjectManager, TimerService, Timer
from loopchain.blockchain import AnnounceNewBlockError
from loopchain.blockchain.blocks import BlockSerializer, BlockVerifier
from loopchain.blockchain.votes.v0_1a import BlockVotes
from loopchain.channel.channel_property import ChannelProperty
from loopchain.protos import message_code

config.log_requests = False
config.log_responses = False
ws_methods = AsyncMethods()
CONNECTION_FAIL_CONDITIONS = {
    message_code.Response.fail_subscribe_limit,
    message_code.Response.fail_connection_closed,
    message_code.Response.fail_connect_to_leader
}


class UnregisteredException(Exception):
    pass


def convert_response_to_dict(response: bytes) -> dict:
    response_dict: dict = json.loads(response)
    response_dict = _check_error_in_response(response_dict)

    return response_dict


def _check_error_in_response(response_dict: dict) -> dict:
    params = response_dict.get('params')
    if params and params.get('code') in CONNECTION_FAIL_CONDITIONS:
        error_msg = params.get('error') or f"Error sent from rs target: {params}"
        raise UnregisteredException(error_msg)

    if "error" in response_dict:
        return ObjectManager().channel_service.shutdown_peer(message=response_dict.get('error'))

    return response_dict


class NodeSubscriber:
    def __init__(self, channel, rs_target):
        scheme = 'wss' if ('https://' in rs_target) else 'ws'
        netloc = parse.urlparse(rs_target).netloc
        self._target_uri = f"{scheme}://{netloc}/api/ws/{channel}"
        self._exception = None
        self._websocket: WebSocketClientProtocol = None
        self._subscribe_event: Event = None
        self._block_time_handler: asyncio.TimerHandle = None

        ws_methods.add(self.node_ws_PublishHeartbeat)
        ws_methods.add(self.node_ws_PublishNewBlock)

        logging.debug(f"websocket target uri : {self._target_uri}")

    def __del__(self):
        # TODO: Check usage
        if self._websocket is not None:
            utils.logger.warning(f"Have to close before delete NodeSubscriber instance({self})")

    async def close(self):
        if self._websocket is not None:
            websocket = self._websocket
            self._websocket = None
            if not websocket.closed:
                logging.debug(f"Closing websocket connection to {self._target_uri}...")
                await websocket.close()

    async def start(self, event, block_height):
        self._subscribe_event = event
        await self._prepare_connection()
        await self._handshake(block_height)
        await self._run()

    async def _prepare_connection(self):
        self._websocket: WebSocketClientProtocol = await websockets.connect(
            uri=self._target_uri,
            max_size=4 * conf.MAX_TX_SIZE_IN_BLOCK,
            loop=MessageQueueService.loop
        )

    async def _handshake(self, block_height):
        try:
            await self._subscribe_request(block_height)
            await self._recv_until_timeout()
            if self._exception:
                raise self._exception
        except Exception as e:
            logging.debug(f"Exception raised during handshake step: {e}", exc_info=True)
            await self.close()
            raise
        else:
            logging.debug(f"Websocket connection is completed, with id({id(self._websocket)})")

    async def _subscribe_request(self, block_height):
        request = Request(
            method="node_ws_Subscribe",
            height=block_height,
            peer_id=ChannelProperty().peer_id
        )
        await self._websocket.send(json.dumps(request))

    async def _recv_until_timeout(self):
        response: bytes = await asyncio.wait_for(
            fut=self._websocket.recv(),
            timeout=2 * conf.TIMEOUT_FOR_WS_HEARTBEAT
        )
        response_dict = convert_response_to_dict(response)

        await ws_methods.dispatch(response_dict)

    async def _run(self):
        try:
            while True:
                if self._exception:
                    raise self._exception
                await self._recv_until_timeout()
        except AnnounceNewBlockError as e:
            logging.error(f"{type(e)} during subscribe, caused by: {e}")
            raise
        except UnregisteredException as e:
            logging.info(f"{type(e)} during subscribe, caused by: {e}")
            raise
        except Exception as e:
            logging.info(f"{type(e)} during subscribe, caused by: {e}")
            raise ConnectionError
        finally:
            await self.close()

    async def node_ws_PublishNewBlock(self, **kwargs):
        self.monitoring_block()
        block_dict, votes_dumped = kwargs.get('block'), kwargs.get('confirm_info', '')
        try:
            votes_serialized = json.loads(votes_dumped)
            vote = BlockVotes.deserialize_votes(votes_serialized)
        except json.JSONDecodeError:
            vote = votes_dumped
        blockchain = ObjectManager().channel_service.block_manager.blockchain

        new_block_height = blockchain.block_versioner.get_height(block_dict)
        if new_block_height > blockchain.block_height:
            block_version = blockchain.block_versioner.get_version(new_block_height)
            block_serializer = BlockSerializer.new(block_version, blockchain.tx_versioner)
            confirmed_block = block_serializer.deserialize(block_dict)

            block_verifier = BlockVerifier.new(block_version, blockchain.tx_versioner)
            block_verifier.invoke_func = blockchain.score_invoke
            reps_getter = blockchain.find_preps_addresses_by_roothash
            try:
                block_verifier.verify(confirmed_block,
                                      blockchain.last_block,
                                      blockchain,
                                      blockchain.get_expected_generator(confirmed_block.header.peer_id),
                                      reps_getter=reps_getter)
            except Exception as e:
                self._exception = AnnounceNewBlockError(f"error: {type(e)}, message: {str(e)}")
            else:
                logging.debug(f"add_confirmed_block height({confirmed_block.header.height}), "
                              f"hash({confirmed_block.header.hash.hex()}), votes_dumped({votes_dumped})")
                ObjectManager().channel_service.block_manager.add_confirmed_block(confirmed_block=confirmed_block,
                                                                                  confirm_info=vote)
            finally:
                ObjectManager().channel_service.reset_block_monitoring_timer()

    async def node_ws_PublishHeartbeat(self, **kwargs):
        def _callback(exception):
            self._exception = exception

        if not self._subscribe_event.is_set():
            # set subscribe_event to transit the state to Watch.
            self._subscribe_event.set()

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

    def monitoring_block(self):
        def _callback_for_no_block_published():
            raise RuntimeError(f"No block published within {conf.TIMEOUT_FOR_BLOCK_MONITOR}. Close Connection.")

        loop = asyncio.get_event_loop()
        self._block_time_handler.cancel()
        self._block_time_handler = loop.call_later(conf.TIMEOUT_FOR_BLOCK_MONITOR, _callback_for_no_block_published)

