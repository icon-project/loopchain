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
import json

import aiohttp
from jsonrpcclient import exceptions, config
from jsonrpcclient.aiohttp_client import AsyncClient, async_timeout
from jsonrpcserver import status
from past.builtins import basestring

from loopchain import configure as conf
from loopchain import utils as util
from loopchain.protos import message_code
from loopchain.rest_server.json_rpc.exception import GenericJsonRpcServerError, JsonError
from loopchain.utils.icon_service.converter_v2 import convert_params, ParamType
from loopchain.utils.message_queue import StubCollection


class CustomAiohttpClient(AsyncClient):
    def __init__(self, session, endpoint):
        super(CustomAiohttpClient, self).__init__(endpoint)
        self.session = session

    async def send_message(self, request):
        with async_timeout.timeout(10):
            async with self.session.post(self.endpoint, data=request) as response:
                response = await response.text()
                return self.process_response(response)

    def process_response(self, response, log_extra=None, log_format=None):
        """
        Process the response and return the 'result' portion if present.

        :param response: The JSON-RPC response string to process.
        :return: The response string, or None
        """
        if response:
            # Log the response before processing it
            self.log_response(response, log_extra, log_format)
            # If it's a json string, parse to object
            if isinstance(response, basestring):
                try:
                    response = json.loads(response)
                except ValueError:
                    raise exceptions.ParseResponseError()
            # Validate the response against the Response schema (raises
            # jsonschema.ValidationError if invalid)
            if config.validate:
                self.validator.validate(response)
            if isinstance(response, list):
                # Batch request - just return the whole response
                return response
            else:
                # If the response was "error", raise to ensure it's handled
                if 'error' in response and response['error'] is not None:
                    # raise exceptions.ReceivedErrorResponse(
                    #     response['error'].get('code'),
                    #     response['error'].get('message'),
                    #     response['error'].get('data'))
                    raise GenericJsonRpcServerError(
                        code=JsonError.INVALID_REQUEST,
                        message=response['error'].get('message'),
                        http_status=status.HTTP_BAD_REQUEST
                    )
                # All was successful, return just the result part
                return response.get('result')
        # No response was given
        return None


async def redirect_request_to_rs(message, rs_target, version=conf.ApiVersion.v3.name):
    method_name = 'icx_sendTransaction'
    rs_url = util.normalize_request_url(f"{'https' if conf.SUBSCRIBE_USE_HTTPS else 'http'}://{rs_target}", version)
    async with aiohttp.ClientSession() as session:
        result = await CustomAiohttpClient(session, rs_url).request(method_name, message)
        util.logger.spam(f"json_rpc_dispatcher:redirect_request_to_rs::{method_name}/{result}")

    return result


async def get_block_v2_by_params(block_height=None, block_hash="", with_commit_state=False):
    channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL
    channel_stub = StubCollection().channel_stubs[channel_name]
    response_code, block_hash, block_data_json, tx_data_json_list = \
        await channel_stub.async_task().get_block_v2(
            block_height=block_height,
            block_hash=block_hash,
            block_data_filter="",
            tx_data_filter=""
        )
    block = json.loads(block_data_json)  # if fail, block = {}

    if block:
        block = convert_params(block, ParamType.get_block)

    result = {
        'response_code': response_code,
        'block': block
    }

    if 'commit_state' in result['block'] and not with_commit_state:
        del result['block']['commit_state']

    return block_hash, result


async def get_block_by_params(block_height=None, block_hash="", with_commit_state=False):
    channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL
    block_data_filter = "prev_block_hash, height, block_hash, merkle_tree_root_hash," \
                        " time_stamp, peer_id, signature"
    if conf.CHANNEL_OPTION[channel_name]['send_tx_type'] == conf.SendTxType.icx:
        tx_data_filter = "icx_origin_data"
    else:
        tx_data_filter = "tx_hash, timestamp, data_string, peer_id"
    channel_stub = StubCollection().channel_stubs[channel_name]
    response_code, block_hash, block_data_json, tx_data_json_list = \
        await channel_stub.async_task().get_block(
            block_height=block_height,
            block_hash=block_hash,
            block_data_filter=block_data_filter,
            tx_data_filter=tx_data_filter
        )

    try:
        block = json.loads(block_data_json) if response_code == message_code.Response.success else {}
    except Exception as e:
        util.logger.error(f"get_block_by_params error caused by : {e}")
        block = {}

    result = {
        'response_code': response_code,
        'block': block
    }

    if 'commit_state' in result['block'] and not with_commit_state:
        del result['block']['commit_state']

    return block_hash, result
