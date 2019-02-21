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
"""A module for restful API server of Peer"""
import _ssl
import base64
import json
import logging
import ssl
from http import HTTPStatus

import grpc
from grpc._channel import _Rendezvous
from sanic import Sanic, response
from sanic.views import HTTPMethodView

from loopchain import configure as conf
from loopchain import utils
from loopchain.components import SingletonMetaClass
from loopchain.protos import loopchain_pb2, message_code
from loopchain.rest_server import PeerServiceStub, RestProperty, json_rpc
from loopchain.utils.message_queue import StubCollection


def get_channel_name_from_args(args) -> str:
    """get channel name from args, if channel is None return conf.LOOPCHAIN_DEFAULT_CHANNEL

    :param args: params
    :return: channel name if args channel is None return conf.LOOPCHAIN_DEFAULT_CHANNEL
    """

    return conf.LOOPCHAIN_DEFAULT_CHANNEL if args.get('channel') is None else args.get('channel')


def get_channel_name_from_json(request_body: dict) -> str:
    """get channel name from json, if json don't have property channel return conf.LOOPCHAIN_DEFAULT_CHANNEL

    :param request_body: json
    :return: channel name if json channel is not exist return conf.LOOPCHAIN_DEFAULT_CHANNEL
    """

    try:
        return request_body['channel']
    except KeyError:
        return conf.LOOPCHAIN_DEFAULT_CHANNEL


class ServerComponents(metaclass=SingletonMetaClass):
    def __init__(self):
        self.__app = Sanic(__name__)
        self.__app.config.KEEP_ALIVE = False

        # Decide whether to create context or not according to whether SSL is applied
        if conf.REST_SSL_TYPE == conf.SSLAuthType.none:
            self.__ssl_context = None
        elif conf.REST_SSL_TYPE == conf.SSLAuthType.server_only:
            self.__ssl_context = {'cert': conf.DEFAULT_SSL_CERT_PATH, 'key': conf.DEFAULT_SSL_KEY_PATH}
        elif conf.REST_SSL_TYPE == conf.SSLAuthType.mutual:
            self.__ssl_context = ssl.SSLContext(_ssl.PROTOCOL_SSLv23)

            self.__ssl_context.verify_mode = ssl.CERT_REQUIRED
            self.__ssl_context.check_hostname = False

            self.__ssl_context.load_verify_locations(cafile=conf.DEFAULT_SSL_TRUST_CERT_PATH)
            self.__ssl_context.load_cert_chain(conf.DEFAULT_SSL_CERT_PATH, conf.DEFAULT_SSL_KEY_PATH)
        else:
            utils.exit_and_msg(
                f"REST_SSL_TYPE must be one of [0,1,2]. But now conf.REST_SSL_TYPE is {conf.REST_SSL_TYPE}")

    @property
    def app(self):
        return self.__app

    @property
    def ssl_context(self):
        return self.__ssl_context

    def set_resource(self):
        self.__app.add_route(json_rpc.NodeDispatcher.dispatch,
                             '/api/node/', methods=['POST'])
        if conf.DISABLE_V1_API:
            self.__app.add_route(Disable.as_view(),
                                 '/api/v1', methods=['POST', 'GET'])
        else:
            self.__app.add_route(Query.as_view(), '/api/v1/query')
            self.__app.add_route(Transaction.as_view(), '/api/v1/transactions')
            self.__app.add_route(ScoreStatus.as_view(), '/api/v1/status/score')
            self.__app.add_route(Blocks.as_view(), '/api/v1/blocks')
            self.__app.add_route(InvokeResult.as_view(),
                                 '/api/v1/transactions/result')
        self.__app.add_route(Status.as_view(), '/api/v1/status/peer')
        self.__app.add_route(Avail.as_view(), '/api/v1/avail/peer')

    def query(self, data, channel):
        return PeerServiceStub().call("Query",
                                      loopchain_pb2.QueryRequest(params=data, channel=channel),
                                      PeerServiceStub.REST_SCORE_QUERY_TIMEOUT)

    def create_transaction(self, data, channel):
        # logging.debug("Grpc Create Tx Data : " + data)
        return PeerServiceStub().call("CreateTx",
                                      loopchain_pb2.CreateTxRequest(data=data, channel=channel),
                                      PeerServiceStub.REST_GRPC_TIMEOUT)

    def get_transaction(self, tx_hash, channel):
        return PeerServiceStub().call("GetTx",
                                      loopchain_pb2.GetTxRequest(tx_hash=tx_hash, channel=channel),
                                      PeerServiceStub.REST_GRPC_TIMEOUT)

    def ready(self, amqp_target, amqp_key):
        StubCollection().amqp_target = amqp_target
        StubCollection().amqp_key = amqp_key

        async def ready_tasks():
            from loopchain import loggers
            loggers.get_preset().update_logger()
            loggers.update_other_loggers()

            logging.debug('rest_server:initialize')
            await StubCollection().create_peer_stub()

            channels_info = await StubCollection().peer_stub.async_task().get_channel_infos()
            channel_name = None
            for channel_name, channel_info in channels_info.items():
                await StubCollection().create_channel_stub(channel_name)
                await StubCollection().create_icon_score_stub(channel_name)

            results = await StubCollection().peer_stub.async_task().get_channel_info_detail(channel_name)

            RestProperty().node_type = conf.NodeType(results[6])
            RestProperty().rs_target = results[3]

            logging.debug(f'rest_server:initialize complete. '
                          f'node_type({RestProperty().node_type}), rs_target({RestProperty().rs_target})')

        self.__app.add_task(ready_tasks())

    def serve(self, amqp_target, amqp_key, api_port):
        self.ready(amqp_target, amqp_key)
        self.__app.run(host='0.0.0.0', port=api_port, debug=False, ssl=self.ssl_context)


class Query(HTTPMethodView):
    required_params = {"method": [str], "params": [dict, str]}
    optional_params = {"channel": [str], "jsonrpc": [str], "id": [str], "sdk_version": [str]}

    async def post(self, request):
        request_body_json = request.json
        result, verify_message = self.__validate_query_request(request_body_json)
        query_data = dict()

        if result is False:
            logging.warning(verify_message)
            message = message_code.get_response(message_code.Response.fail_validate_params)
            query_data['response_code'] = str(message[0].value)
            query_data['response'] = message[1] + '. ' + verify_message
        else:
            request_body_dump = json.dumps(request_body_json)
            channel = get_channel_name_from_json(request.json)

            try:
                grpc_response = ServerComponents().query(request_body_dump, channel)
                if grpc_response is None:
                    query_data['response'] = str(grpc_response)
                    query_data['response_code'] = str(message_code.Response.not_treat_message_code)
                else:
                    logging.debug(f"query result : {grpc_response}")
                    query_data['response_code'] = str(grpc_response.response_code)
                    try:
                        query_data['response'] = json.loads(grpc_response.response)

                    except json.JSONDecodeError as e:
                        logging.warning("your response is not json, your response(" + str(grpc_response.response) + ")")
                        query_data['response'] = grpc_response.response

            except _Rendezvous as e:
                logging.error(f'Execute Query Error : {e}')
                if e.code() == grpc.StatusCode.DEADLINE_EXCEEDED:
                    logging.debug("gRPC timeout !!!")
                    query_data['response_code'] = str(message_code.Response.timeout_exceed)

        return response.json(query_data)

    def __validate_query_request(self, request_body_json: dict) -> tuple:
        """ validation check for request body of a query
        :param request_body_json: Request body
        :return: (is_validation, message): A tuple includes validation and message.
        """
        message = "Valid parameters."

        if len(request_body_json) == 0:
            message = "Request body is None."
            return False, message
        else:
            for param, param_value in request_body_json.items():
                if self.optional_params.get(param) is None:
                    if self.required_params.get(param) is None:
                        message = "You sent any invalid parameter."
                        return False, message
                    elif type(param_value) not in self.required_params[param]:
                        message = f"required '{param}' must be {self.required_params[param]} type." \
                                  f" But {param} is {type(param_value)}"
                        return False, message
                elif type(param_value) not in self.optional_params[param]:
                    message = f"optional '{param}' must be {self.optional_params[param]} type." \
                              f" But this is {type(param_value)}"
                    return False, message

            for param in self.required_params:
                if request_body_json.get(param) is None:
                    message = "You missed any required parameter."
                    return False, message

            return True, message


class Transaction(HTTPMethodView):
    async def get(self, request):
        args = request.raw_args
        tx_hash = args['hash']
        tx_data = dict()

        if utils.is_hex(tx_hash):
            grpc_response = ServerComponents().get_transaction(tx_hash, get_channel_name_from_args(args))
            tx_data['response_code'] = str(grpc_response.response_code)
            tx_data['data'] = ""
            if len(grpc_response.data) is not 0:
                try:
                    tx_data['data'] = json.loads(grpc_response.data)
                except json.JSONDecodeError as e:
                    logging.warning("your data is not json, your data(" + str(grpc_response.data) + ")")
                    tx_data['data'] = grpc_response.data

            tx_data['meta'] = ""
            if len(grpc_response.meta) is not 0:
                tx_data['meta'] = json.loads(grpc_response.meta)

            tx_data['more_info'] = grpc_response.more_info
            b64_sign = base64.b64encode(grpc_response.signature)
            tx_data['signature'] = b64_sign.decode()
            b64_public_key = base64.b64encode(grpc_response.public_key)
            tx_data['public_key'] = b64_public_key.decode()
        else:
            tx_data['response_code'] = str(message_code.Response.fail_validate_params.value)
            tx_data['message'] = "Invalid transaction hash."

        return response.json(tx_data)

    async def post(self, request):
        # logging.debug("RestServer Post Transaction")
        request_body = json.dumps(request.json)
        logging.debug("Transaction Request Body : " + request_body)
        channel = get_channel_name_from_json(request.json)
        grpc_response = ServerComponents().create_transaction(request_body, channel)

        tx_data = dict()

        if grpc_response is not None:
            tx_data['response_code'] = str(grpc_response.response_code)
            tx_data['tx_hash'] = grpc_response.tx_hash
            tx_data['more_info'] = grpc_response.more_info
        logging.debug('create tx result : ' + str(tx_data))

        return response.json(tx_data)


class InvokeResult(HTTPMethodView):
    async def get(self, request):
        logging.debug('transaction result')
        args = request.raw_args
        tx_hash = args['hash']
        verify_result = dict()
        if utils.is_hex(tx_hash):
            logging.debug('tx_hash : ' + tx_hash)
            channel_name = get_channel_name_from_args(args)
            grpc_response = PeerServiceStub().get_invoke_result(channel=channel_name, tx_hash=tx_hash)
            verify_result['response_code'] = str(grpc_response.response_code)
            if len(grpc_response.result) is not 0:
                try:
                    result = json.loads(grpc_response.result)
                    result['jsonrpc'] = '2.0'
                    verify_result['response'] = result
                except json.JSONDecodeError as e:
                    logging.warning("your data is not json, your data(" + str(grpc_response.data) + ")")
                    verify_result['response_code'] = str(message_code.Response.fail.value)
            else:
                verify_result['response_code'] = str(message_code.Response.fail.value)
        else:
            verify_result['response_code'] = str(message_code.Response.fail_validate_params.value)
            verify_result['message'] = "Invalid transaction hash."
        return response.json(verify_result)


class Status(HTTPMethodView):
    async def get(self, request):
        return response.json(PeerServiceStub().get_status(get_channel_name_from_args(request.raw_args)))


class Avail(HTTPMethodView):
    async def get(self, request):
        status = HTTPStatus.OK
        result = PeerServiceStub().get_status(
            get_channel_name_from_args(request.raw_args)
        )

        # parse result and set HTTPStatus error while service is not avail.
        # util.logger.spam(f"result({result['status']})")
        if result['status'] != "Service is online: 0":
            status = HTTPStatus.SERVICE_UNAVAILABLE

        return response.json(
            result,
            status=status
        )


class ScoreStatus(HTTPMethodView):
    async def get(self, request):
        channel_name = get_channel_name_from_args(request.raw_args)
        score_stub = StubCollection().score_stubs[channel_name]
        status = await score_stub.async_task().status()
        return response.json(status)


class Blocks(HTTPMethodView):
    async def get(self, request):
        args = request.raw_args
        channel = get_channel_name_from_args(args)
        block_data = dict()

        if 'hash' in args:
            block_hash = args['hash']

            if utils.is_hex(block_hash):
                grpc_response = PeerServiceStub().get_block(channel=channel, block_hash=block_hash)
                logging.debug(f"response : {grpc_response}")
                block_data['block_hash'] = grpc_response.block_hash
                block_data['block_data_json'] = json.loads(grpc_response.block_data_json)

                if len(grpc_response.tx_data_json) < 1:
                    block_data['tx_data_json'] = ''
                else:
                    tx_data = list()
                    tx_json_data = grpc_response.tx_data_json

                    for i in range(0, len(tx_json_data)):
                        tx_data.append(json.loads(tx_json_data[i]))

                    block_data['tx_data_json'] = json.loads(json.dumps(tx_data))
            else:
                block_data['response_code'] = str(message_code.Response.fail_validate_params.value)
                block_data['message'] = "Invalid transaction hash."
        else:
            block_hash = PeerServiceStub().get_last_block_hash(channel=channel)
            grpc_response = PeerServiceStub().get_block(channel=channel, block_hash=block_hash)
            logging.debug(f"response : {grpc_response}")
            block_data['response_code'] = grpc_response.response_code
            block_data['block_hash'] = grpc_response.block_hash
            block_data['block_data_json'] = json.loads(grpc_response.block_data_json)

        return response.json(block_data)


class Disable(HTTPMethodView):
    async def get(self, request):
        return response.text("This api version not support any more!")

    async def post(self, request):
        return response.text("This api version not support any more!")

