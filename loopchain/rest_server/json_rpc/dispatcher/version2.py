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
"""json rpc dispatcher version 2"""

import json
import logging

from jsonrpcserver import config
from jsonrpcserver.aio import AsyncMethods
from sanic import response as sanic_response

import loopchain.utils as util
from loopchain import configure as conf
from loopchain.protos import message_code
from loopchain.rest_server import RestProperty
from loopchain.utils.json_rpc import (get_block_by_params,
                                      redirect_request_to_rs)
from loopchain.utils.message_queue import StubCollection

config.log_requests = False
config.log_responses = False

methods = AsyncMethods()


class Version2Dispatcher:
    @staticmethod
    async def dispatch(request):
        req = request.json
        req['params'] = req.get('params', {})
        req['params']['method'] = req.get('method')

        response = await methods.dispatch(req)
        return sanic_response.json(response, status=response.http_status, dumps=json.dumps)

    @staticmethod
    @methods.add
    async def icx_sendTransaction(**kwargs):
        if RestProperty().node_type == conf.NodeType.CitizenNode:
            return await redirect_request_to_rs(kwargs, RestProperty().rs_target, conf.ApiVersion.v2.name)

        channel_stub = StubCollection().channel_stubs[conf.LOOPCHAIN_DEFAULT_CHANNEL]
        response_code, tx_hash = await channel_stub.async_task().create_icx_tx(kwargs)

        response_data = {'response_code': response_code}
        if response_code != message_code.Response.success:
            response_data['message'] = message_code.responseCodeMap[response_code][1]
        else:
            response_data['tx_hash'] = tx_hash

        return response_data

    @staticmethod
    @methods.add
    async def icx_getTransactionResult(**kwargs):
        channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL
        channel_stub = StubCollection().channel_stubs[channel_name]
        verify_result = {}

        message = None

        tx_hash = kwargs["tx_hash"]
        if util.is_hex(tx_hash):
            response_code, result = await channel_stub.async_task().get_invoke_result(tx_hash)
            if response_code == message_code.Response.success:
                # loopchain success
                if result:
                    try:
                        # apply tx_result_convert
                        result_dict = json.loads(result)
                        fail_status = bool(result_dict.get('failure'))
                        if fail_status:
                            error_code = message_code.Response.fail_validate_params
                            message = "Invalid transaction hash."
                        else:
                            error_code = message_code.Response.success
                    except json.JSONDecodeError as e:
                        error_message = f"your result is not json, result({result}), {e}"
                        logging.warning(error_message)
                        error_code = message_code.Response.fail_validate_params
                        message = error_message
                else:
                    error_code = message_code.Response.fail_validate_params
                    message = 'tx_result is empty'
            else:
                error_code = message_code.Response.fail_validate_params
                message = "Invalid transaction hash."
        else:
            # fail
            error_code = message_code.Response.fail_validate_params
            message = "response_code is fail"

        # parsing response
        verify_result['response_code'] = str(error_code)
        if error_code == message_code.Response.success:
            verify_result['response'] = {'code': error_code}
        if message:
            verify_result['message'] = message

        return verify_result

    @staticmethod
    @methods.add
    async def icx_getBalance(**kwargs):
        channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL

        score_stub = StubCollection().score_stubs[channel_name]
        response_code, response = await score_stub.async_task().query(json.dumps(kwargs))

        response = json.loads(response)
        response['response_code'] = response_code
        return response

    @staticmethod
    @methods.add
    async def icx_getTotalSupply(**kwargs):
        channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL
        score_stub = StubCollection().score_stubs[channel_name]
        response_code, response = await score_stub.async_task().query(json.dumps(kwargs))

        response = json.loads(response)
        response['response_code'] = response_code
        return response

    @staticmethod
    @methods.add
    async def icx_getLastBlock(**kwargs):
        block_hash, response = await get_block_by_params(block_height=-1)
        util.logger.spam(f"JSONRPC_v2:icx_getLastBlock::response_code({response['response_code']}), "
                         f"block_hash({block_hash})")
        return response

    @staticmethod
    @methods.add
    async def icx_getBlockByHash(**kwargs):
        block_hash, response = await get_block_by_params(block_hash=kwargs["hash"])
        util.logger.spam(f"JSONRPC_v2:icx_getBlockByHash::response_code({response['response_code']}), "
                         f"block_hash({block_hash})")
        return response

    @staticmethod
    @methods.add
    async def icx_getBlockByHeight(**kwargs):
        block_hash, response = await get_block_by_params(block_height=int(kwargs["height"]))
        util.logger.spam(f"JSONRPC_v2:icx_getBlockByHeight::response_code({response['response_code']}), "
                         f"block_height({kwargs['height']})")
        return response

    @staticmethod
    @methods.add
    async def icx_getTransactionByAddress(**kwargs):
        channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL

        address = kwargs.get("address", None)
        index = kwargs.get("index", None)

        if address is None or index is None:
            return {
                'response_code': message_code.Response.fail_illegal_params,
                'message': message_code.get_response_msg(message_code.Response.fail_illegal_params)
            }

        channel_stub = StubCollection().channel_stubs[channel_name]
        tx_list, next_index = await channel_stub.async_task().get_tx_by_address(
            address=address,
            index=index
        )

        response = {
            'next_index': next_index,
            'response': tx_list[:-1],
            'response_code': message_code.Response.success
        }
        return response
