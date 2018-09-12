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
import uuid
from functools import partial

from loopchain.baseservice import (CommonSubprocess, Monitor, ObjectManager,
                                   RestStubManager, StubManager)
from loopchain.blockchain import *
from loopchain.container import CommonService, RestService
from loopchain.peer import PeerInnerService, PeerOuterService
from loopchain.peer.icx_authorization import IcxAuthorization
from loopchain.protos import loopchain_pb2, loopchain_pb2_grpc, message_code
from loopchain.rest_server import RestProxyServer
from loopchain.tools.signature_helper import PublicVerifier
from loopchain.utils import command_arguments, loggers
from loopchain.utils.message_queue import StubCollection


class PeerService:
    """Peer Service 의 main Class
    outer 와 inner gRPC 인터페이스를 가진다.
    서비스 루프 및 공통 요소는 commonservice 를 통해서 처리한다.
    channel 관련 instance 는 channel manager 를 통해서 관리한다.
    """

    def __init__(self, group_id=None, radio_station_ip=None, radio_station_port=None, node_type=None):
        """Peer는 Radio Station 에 접속하여 leader 및 다른 Peer에 대한 접속 정보를 전달 받는다.

        :param group_id: Peer Group 을 구분하기 위한 ID, None 이면 Single Peer Group 이 된다. (peer_id is group_id)
        conf.PEER_GROUP_ID 를 사용하면 configure 파일에 저장된 값을 group_id 로 사용하게 된다.
        :param radio_station_ip: RS IP
        :param radio_station_port: RS Port
        :return:
        """
        radio_station_ip = radio_station_ip or conf.IP_RADIOSTATION
        radio_station_port = radio_station_port or conf.PORT_RADIOSTATION
        node_type = node_type or conf.NodeType.CommunityNode

        self.is_support_node_function = \
            partial(conf.NodeType.is_support_node_function, node_type=node_type)

        util.logger.spam(f"Your Peer Service runs on debugging MODE!")
        util.logger.spam(f"You can see many terrible garbage logs just for debugging, DO U Really want it?")

        # process monitor must start before any subprocess
        if conf.ENABLE_PROCESS_MONITORING:
            Monitor().start()

        self.__node_type = node_type

        self.__radio_station_target = radio_station_ip + ":" + str(radio_station_port)
        logging.info("Set Radio Station target is " + self.__radio_station_target)

        self.__radio_station_stub = None

        self.__level_db = None
        self.__level_db_path = ""

        self.__peer_id = None
        self.__group_id = group_id
        if self.__group_id is None and conf.PEER_GROUP_ID != "":
            self.__group_id = conf.PEER_GROUP_ID

        self.__common_service = None
        self.__channel_infos = None

        self.__rest_service = None
        self.__rest_proxy_server = None

        # peer status cache for channel
        self.status_cache = {}  # {channel:status}

        self.__score = None
        self.__peer_target = None
        self.__rest_target = None
        self.__inner_target = None
        self.__peer_port = 0

        # gRPC service for Peer
        self.__inner_service: PeerInnerService = None
        self.__outer_service: PeerOuterService = None
        self.__channel_services = {}

        self.__reset_voter_in_progress = False
        self.__json_conf_path = None

        ObjectManager().peer_service = self

    @property
    def common_service(self):
        return self.__common_service

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
    def json_conf_path(self):
        return self.__json_conf_path

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
    def stub_to_radiostation(self) -> StubManager:
        stub_type = loopchain_pb2_grpc.PeerServiceStub
        if self.is_support_node_function(conf.NodeFunction.Vote):
            stub_type = loopchain_pb2_grpc.RadioStationStub

        if self.__radio_station_stub is None:
            if self.is_support_node_function(conf.NodeFunction.Vote):
                self.__radio_station_stub = StubManager.get_stub_manager_to_server(
                    self.__radio_station_target,
                    stub_type,
                    conf.CONNECTION_RETRY_TIMEOUT_TO_RS,
                    ssl_auth_type=conf.GRPC_SSL_TYPE)
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
    def group_id(self):
        if self.__group_id is None:
            self.__group_id = self.__peer_id
        return self.__group_id

    @property
    def radio_station_target(self):
        return self.__radio_station_target

    def rotate_next_leader(self, channel_name):
        """Find Next Leader Id from peer_list and reset leader to that peer"""

        # logging.debug("rotate next leader...")
        util.logger.spam(f"peer_service:rotate_next_leader")
        peer_manager = self.__channel_manager.get_peer_manager(channel_name)
        next_leader = peer_manager.get_next_leader_peer(is_only_alive=True)

        # Check Next Leader is available...
        if next_leader is not None and next_leader.peer_id != self.peer_id:
            try:
                stub_manager = peer_manager.get_peer_stub_manager(next_leader)
                response = stub_manager.call(
                    "Request", loopchain_pb2.Message(
                        code=message_code.Request.status,
                        channel=channel_name,
                        message="get_leader_peer"
                    ), is_stub_reuse=True)

                # Peer 가 leader 로 변경되는데 시간이 필요함으로 접속 여부만 확인한다.
                # peer_status = json.loads(response.status)
                # if peer_status["peer_type"] != str(loopchain_pb2.BLOCK_GENERATOR):
                #     logging.warning("next rotate is not a leader")
                #     raise Exception

            except Exception as e:
                logging.warning(f"rotate next leader exceptions({e})")
                next_leader = peer_manager.leader_complain_to_rs(conf.ALL_GROUP_ID)

        if next_leader is not None:
            self.reset_leader(next_leader.peer_id, channel_name)
        else:
            util.logger.warning(f"peer_service:rotate_next_leader next_leader is None({next_leader})")

    def service_stop(self):
        self.__common_service.stop()

    def __get_channel_infos(self):
        # util.logger.spam(f"__get_channel_infos:node_type::{self.__node_type}")
        if self.is_support_node_function(conf.NodeFunction.Vote):
            response = self.stub_to_radiostation.call_in_times(
                method_name="GetChannelInfos",
                message=loopchain_pb2.GetChannelInfosRequest(
                    peer_id=self.__peer_id,
                    peer_target=self.__peer_target,
                    group_id=self.group_id),
                retry_times=conf.CONNECTION_RETRY_TIMES_TO_RS,
                is_stub_reuse=False,
                timeout=conf.CONNECTION_TIMEOUT_TO_RS
            )
            # util.logger.spam(f"__get_channel_infos:response::{response}")

            if not response:
                return None
            logging.info(f"Connect to channels({util.pretty_json(response.channel_infos)})")
            channels = json.loads(response.channel_infos)
        else:
            response = self.stub_to_radiostation.call_in_times(
                method_name="GetChannelInfos",
                message={}
            )
            channels = {channel: value for channel, value in response["channel_infos"].items()
                        if conf.CHANNEL_OPTION[channel]['send_tx_type'] == conf.SendTxType.icx}
            # util.logger.spam(f"__get_channel_infos:channels::{channels}")

        return channels

    def __init_port(self, port):
        # service 초기화 작업
        target_ip = util.get_private_ip()
        self.__peer_target = util.get_private_ip() + ":" + str(port)
        self.__peer_port = int(port)

        rest_port = int(port) + conf.PORT_DIFF_REST_SERVICE_CONTAINER
        self.__rest_target = f"{target_ip}:{rest_port}"

        logging.info("Start Peer Service at port: " + str(port))

    def __init_level_db(self):
        # level db for peer service not a channel, It store unique peer info like peer_id
        self.__level_db, self.__level_db_path = util.init_level_db(
            level_db_identity=self.__peer_target,
            allow_rename_path=False
        )

    def __run_rest_services(self, port):
        if conf.ENABLE_REST_SERVICE and not conf.USE_EXTERNAL_REST:
            if conf.USE_GUNICORN_HA_SERVER:
                # Run web app on gunicorn in another process.
                self.__rest_proxy_server = RestProxyServer(int(port))
            else:
                # Run web app as it is.
                logging.debug(f'Launch Sanic RESTful server. Port = {port}')
                self.__rest_service = RestService(int(port))

    def __make_peer_id(self):
        """네트워크에서 Peer 를 식별하기 위한 UUID를 level db 에 생성한다.
        """
        if conf.CHANNEL_OPTION[conf.LOOPCHAIN_DEFAULT_CHANNEL]['send_tx_type'] == conf.SendTxType.icx:
            self.__peer_id = IcxAuthorization(conf.LOOPCHAIN_DEFAULT_CHANNEL).address
        else:
            try:
                uuid_bytes = bytes(self.__level_db.Get(conf.LEVEL_DB_KEY_FOR_PEER_ID))
                peer_id = uuid.UUID(bytes=uuid_bytes)
            except KeyError:  # It's first Run
                peer_id = None

            if peer_id is None:
                peer_id = uuid.uuid1()
                logging.info("make new peer_id: " + str(peer_id))
                self.__level_db.Put(conf.LEVEL_DB_KEY_FOR_PEER_ID, peer_id.bytes)

            self.__peer_id = str(peer_id)

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
            if value[PublicVerifier.KEY_LOAD_TYPE] == conf.KeyLoadType.KMS_LOAD:
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

    def run_common_service(self):
        inner_service_port = conf.PORT_INNER_SERVICE or (self.__peer_port + conf.PORT_DIFF_INNER_SERVICE)
        self.__inner_target = conf.IP_LOCAL + ":" + str(inner_service_port)

        self.__common_service = CommonService(loopchain_pb2, inner_service_port)
        self.__common_service.start(str(self.__peer_port), self.__peer_id, self.__group_id)

        loopchain_pb2_grpc.add_PeerServiceServicer_to_server(self.__outer_service, self.__common_service.outer_server)

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
        self.__init_level_db()

        self.__make_peer_id()

        StubCollection().amqp_target = amqp_target
        StubCollection().amqp_key = amqp_key

        peer_queue_name = conf.PEER_QUEUE_NAME_FORMAT.format(amqp_key=amqp_key)
        self.__outer_service = PeerOuterService()
        self.__inner_service = PeerInnerService(
            amqp_target, peer_queue_name, conf.AMQP_USERNAME, conf.AMQP_PASSWORD, peer_service=self)

        self.__channel_infos = self.__get_channel_infos()
        if not self.__channel_infos:
            util.exit_and_msg("There is no peer_list, initial network is not allowed without RS!")

        self.__run_rest_services(port)
        self.run_common_service()

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

        self.__common_service.wait()

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

            self.service_stop()
            loop.stop()

        loop = self.__inner_service.loop
        loop.create_task(_close())

    async def serve_channels(self):
        for i, channel_name in enumerate(self.__channel_infos.keys()):
            score_port = self.__peer_port + conf.PORT_DIFF_SCORE_CONTAINER + conf.PORT_DIFF_BETWEEN_SCORE_CONTAINER * i

            args = ['python3', '-m', 'loopchain', 'channel']
            args += ['-p', str(score_port)]
            args += ['--channel', str(channel_name)]
            args += command_arguments.get_raw_commands_by_filter(
                command_arguments.Type.Develop,
                command_arguments.Type.AMQPTarget,
                command_arguments.Type.AMQPKey,
                command_arguments.Type.ConfigurationFilePath
            )

            service = CommonSubprocess(args)

            channel_stub = StubCollection().channel_stubs[channel_name]
            await channel_stub.async_task().hello()

            self.__channel_services[channel_name] = service

    async def ready_tasks(self):
        await StubCollection().create_peer_stub()  # for getting status info

        for channel_name, channel_info in self.__channel_infos.items():
            await StubCollection().create_channel_stub(channel_name)

            if conf.USE_EXTERNAL_SCORE:
                await StubCollection().create_icon_score_stub(channel_name)
            else:
                await StubCollection().create_score_stub(channel_name, channel_info['score_package'])
