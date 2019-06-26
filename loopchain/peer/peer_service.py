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
"""loopchain main peer service.
It has secure outer service for p2p consensus and status monitoring.
And also has insecure inner service for inner process modules."""

import multiprocessing
import signal
import timeit
import json
from functools import partial

import grpc

from loopchain.baseservice import CommonSubprocess
from loopchain.baseservice import StubManager, RestStubManager
from loopchain.blockchain import *
from loopchain.container import RestService
from loopchain.crypto.signature import Signer
from loopchain.peer import PeerInnerService, PeerOuterService
from loopchain.protos import loopchain_pb2, loopchain_pb2_grpc
from loopchain.tools.grpc_helper import GRPCHelper
from loopchain.utils import loggers, command_arguments
from loopchain.utils.message_queue import StubCollection


class PeerService:
    """Peer Service 의 main Class
    outer 와 inner gRPC 인터페이스를 가진다.
    서비스 루프 및 공통 요소는 commonservice 를 통해서 처리한다.
    channel 관련 instance 는 channel manager 를 통해서 관리한다.
    """

    def __init__(self, radio_station_target=None, node_type=None):
        """Peer는 Radio Station 에 접속하여 leader 및 다른 Peer에 대한 접속 정보를 전달 받는다.

        :param radio_station_ip: RS IP
        :param radio_station_port: RS Port
        :return:
        """
        node_type = node_type or conf.NodeType.CommunityNode

        self.is_support_node_function = \
            partial(conf.NodeType.is_support_node_function, node_type=node_type)

        utils.logger.spam(f"Your Peer Service runs on debugging MODE!")
        utils.logger.spam(f"You can see many terrible garbage logs just for debugging, DO U Really want it?")

        self.__node_type = node_type

        self.__radio_station_target = radio_station_target
        logging.info("Set Radio Station target is " + self.__radio_station_target)

        self.__radio_station_stub = None
        self.__peer_id = None
        self.p2p_outer_server: grpc.Server = None
        self.__channel_infos = None

        self.__rest_service = None
        self.__rest_proxy_server = None

        # peer status cache for channel
        self.status_cache = {}  # {channel:status}

        self.__score = None
        self.__peer_target = None
        self.__rest_target = None
        self.__peer_port = 0

        # gRPC service for Peer
        self.__inner_service: PeerInnerService = None
        self.__outer_service: PeerOuterService = None
        self.__channel_services = {}

        self.__node_keys: dict = {}

        ObjectManager().peer_service = self

    @property
    def inner_service(self):
        return self.__inner_service

    @property
    def outer_service(self):
        return self.__outer_service

    @property
    def peer_target(self):
        return self.__peer_target

    @property
    def rest_target(self):
        return self.__rest_target

    @property
    def channel_infos(self):
        return self.__channel_infos

    @property
    def node_type(self):
        return self.__node_type

    @property
    def radio_station_target(self):
        return self.__radio_station_target

    @property
    def stub_to_radiostation(self):
        if self.__radio_station_stub is None:
            if self.is_support_node_function(conf.NodeFunction.Vote):
                if conf.ENABLE_REP_RADIO_STATION:
                    self.__radio_station_stub = StubManager.get_stub_manager_to_server(
                        self.__radio_station_target,
                        loopchain_pb2_grpc.RadioStationStub,
                        conf.CONNECTION_RETRY_TIMEOUT_TO_RS,
                        ssl_auth_type=conf.GRPC_SSL_TYPE)
                else:
                    self.__radio_station_stub = None
            else:
                self.__radio_station_stub = RestStubManager(self.__radio_station_target)

        return self.__radio_station_stub

    @property
    def peer_port(self):
        return self.__peer_port

    @property
    def peer_id(self):
        return self.__peer_id

    @property
    def node_keys(self):
        return self.__node_keys

    def p2p_server_stop(self):
        self.p2p_outer_server.stop(None)

    def __get_channel_infos(self):
        if self.is_support_node_function(conf.NodeFunction.Vote) and conf.ENABLE_REP_RADIO_STATION:
            response = self.stub_to_radiostation.call_in_times(
                method_name="GetChannelInfos",
                message=loopchain_pb2.GetChannelInfosRequest(
                    peer_id=self.__peer_id,
                    peer_target=self.__peer_target,
                    group_id=self.__peer_id),
                retry_times=conf.CONNECTION_RETRY_TIMES_TO_RS,
                is_stub_reuse=False,
                timeout=conf.CONNECTION_TIMEOUT_TO_RS
            )
            # util.logger.spam(f"__get_channel_infos:response::{response}")

            if not response:
                return None
            logging.info(f"Connect to channels({utils.pretty_json(response.channel_infos)})")
            return json.loads(response.channel_infos)
        return {channel: dict() for channel in conf.CHANNEL_OPTION}

    def __init_port(self, port):
        # service 초기화 작업
        target_ip = utils.get_private_ip()
        self.__peer_target = f"{target_ip}:{port}"
        self.__peer_port = int(port)

        rest_port = int(port) + conf.PORT_DIFF_REST_SERVICE_CONTAINER
        self.__rest_target = f"{target_ip}:{rest_port}"

        logging.info("Start Peer Service at port: " + str(port))

    def __run_rest_services(self, port):
        if conf.ENABLE_REST_SERVICE and conf.RUN_ICON_IN_LAUNCHER:
            logging.debug(f'Launch Sanic RESTful server. '
                          f'Port = {int(port) + conf.PORT_DIFF_REST_SERVICE_CONTAINER}')
            self.__rest_service = RestService(int(port))

    def __init_key_by_channel(self):
        for channel in conf.CHANNEL_OPTION:
            signer = Signer.from_channel(channel)
            if channel == conf.LOOPCHAIN_DEFAULT_CHANNEL:
                self.__make_peer_id(signer.address)
            self.__node_keys[channel] = signer.private_key.private_key

    def __make_peer_id(self, address):
        self.__peer_id = address

        logger_preset = loggers.get_preset()
        logger_preset.peer_id = self.peer_id
        logger_preset.update_logger()

        logging.info(f"run peer_id : {self.__peer_id}")

    def timer_test_callback_function(self, message):
        logging.debug(f'timer test callback function :: ({message})')

    @staticmethod
    def __get_use_kms():
        if conf.GRPC_SSL_KEY_LOAD_TYPE == conf.KeyLoadType.KMS_LOAD:
            return True
        for value in conf.CHANNEL_OPTION.values():
            if value["key_load_type"] == conf.KeyLoadType.KMS_LOAD:
                return True
        return False

    def __init_kms_helper(self, agent_pin):
        if self.__get_use_kms():
            from loopchain.tools.kms_helper import KmsHelper
            KmsHelper().set_agent_pin(agent_pin)

    def __close_kms_helper(self):
        if self.__get_use_kms():
            from loopchain.tools.kms_helper import KmsHelper
            KmsHelper().remove_agent_pin()

    def run_p2p_server(self):
        self.p2p_outer_server = GRPCHelper().start_outer_server(str(self.__peer_port))
        loopchain_pb2_grpc.add_PeerServiceServicer_to_server(self.__outer_service, self.p2p_outer_server)

    def serve(self,
              port,
              agent_pin: str=None,
              amqp_target: str=None,
              amqp_key: str=None,
              event_for_init: multiprocessing.Event=None):
        """start func of Peer Service ===================================================================

        :param port:
        :param agent_pin: kms agent pin
        :param amqp_target: rabbitmq host target
        :param amqp_key: sharing queue key
        :param event_for_init: set when peer initiates
        """

        amqp_target = amqp_target or conf.AMQP_TARGET
        amqp_key = amqp_key or conf.AMQP_KEY

        stopwatch_start = timeit.default_timer()

        self.__init_kms_helper(agent_pin)
        self.__init_port(port)
        self.__init_key_by_channel()

        StubCollection().amqp_target = amqp_target
        StubCollection().amqp_key = amqp_key

        peer_queue_name = conf.PEER_QUEUE_NAME_FORMAT.format(amqp_key=amqp_key)
        self.__outer_service = PeerOuterService()
        self.__inner_service = PeerInnerService(
            amqp_target, peer_queue_name, conf.AMQP_USERNAME, conf.AMQP_PASSWORD, peer_service=self)

        self.__reset_channel_infos()

        self.__run_rest_services(port)
        self.run_p2p_server()

        self.__close_kms_helper()

        stopwatch_duration = timeit.default_timer() - stopwatch_start
        logging.info(f"Start Peer Service at port: {port} start duration({stopwatch_duration})")

        async def _serve():
            await self.ready_tasks()
            await self.__inner_service.connect(conf.AMQP_CONNECTION_ATTEMPS, conf.AMQP_RETRY_DELAY, exclusive=True)

            if conf.CHANNEL_BUILTIN:
                await self.serve_channels()

            if event_for_init is not None:
                event_for_init.set()

            logging.info(f'peer_service: init complete peer: {self.peer_id}')

        loop = self.__inner_service.loop
        loop.create_task(_serve())
        loop.add_signal_handler(signal.SIGINT, self.close)
        loop.add_signal_handler(signal.SIGTERM, self.close)

        try:
            loop.run_forever()
        finally:
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.close()

        # process monitor must stop monitoring before any subprocess stop
        # Monitor().stop()

        logging.info("Peer Service Ended.")
        if self.__rest_service is not None:
            self.__rest_service.stop()

        if self.__rest_proxy_server is not None:
            self.__rest_proxy_server.stop()

    def close(self):
        async def _close():
            for channel_stub in StubCollection().channel_stubs.values():
                await channel_stub.async_task().stop("Close")

            self.p2p_server_stop()
            loop.stop()

        loop = self.__inner_service.loop
        loop.create_task(_close())

    async def serve_channels(self):
        for i, channel_name in enumerate(conf.CHANNEL_OPTION):
            score_port = self.__peer_port + conf.PORT_DIFF_SCORE_CONTAINER + conf.PORT_DIFF_BETWEEN_SCORE_CONTAINER * i

            args = ['python3', '-m', 'loopchain', 'channel']
            args += ['-p', str(score_port)]
            args += ['--channel', str(channel_name)]
            args += command_arguments.get_raw_commands_by_filter(
                command_arguments.Type.Develop,
                command_arguments.Type.AMQPTarget,
                command_arguments.Type.AMQPKey,
                command_arguments.Type.ConfigurationFilePath,
                command_arguments.Type.RadioStationTarget
            )

            service = CommonSubprocess(args)

            channel_stub = StubCollection().channel_stubs[channel_name]
            await channel_stub.async_task().hello()

            self.__channel_services[channel_name] = service

    async def ready_tasks(self):
        await StubCollection().create_peer_stub()  # for getting status info

        for channel_name in conf.CHANNEL_OPTION:
            await StubCollection().create_channel_stub(channel_name)
            await StubCollection().create_channel_tx_receiver_stub(channel_name)

            await StubCollection().create_icon_score_stub(channel_name)

    def __reset_channel_infos(self):
        self.__channel_infos = self.__get_channel_infos()

    async def change_node_type(self, node_type):
        if self.__node_type.value == node_type:
            utils.logger.warning(f"Does not change node type because new note type equals current node type")
            return

        self.__node_type = conf.NodeType(node_type)
        self.is_support_node_function = \
            partial(conf.NodeType.is_support_node_function, node_type=node_type)

        self.__radio_station_stub = None

        self.__reset_channel_infos()
