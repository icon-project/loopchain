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
""" A class for gRPC service of Radio station """

import logging
import multiprocessing
import random
import signal
import timeit
import time

import loopchain.utils as util
from loopchain import configure as conf
from loopchain.baseservice import ObjectManager, TimerService, Timer
from loopchain.container import RestServiceRS, CommonService
from loopchain.peer import ChannelManager
from loopchain.protos import loopchain_pb2_grpc
from loopchain.radiostation import OuterService, AdminService, AdminManager
from loopchain.utils import loggers
from .certificate_authorization import CertificateAuthorization

# Changing the import location will cause a pickle error.
import loopchain_pb2


class RadioStationService:
    """Radiostation 의 main Class
    peer 를 위한 outer service 와 관리용 admin service 두개의 gRPC interface 를 가진다.
    """

    # 인증처리
    __ca = None

    def __init__(self, radio_station_ip=None, cert_path=None, cert_pass=None, rand_seed=None):
        """RadioStation Init

        :param radio_station_ip: radioStation Ip
        :param cert_path: RadioStation 인증서 디렉토리 경로
        :param cert_pass: RadioStation private key password
        """
        logger_preset = loggers.get_preset()
        logger_preset.peer_id = "RadioStation"
        logger_preset.update_logger()

        if radio_station_ip is None:
            radio_station_ip = conf.IP_RADIOSTATION
        logging.info("Set RadioStationService IP: " + radio_station_ip)
        if cert_path is not None:
            logging.info("CA Certificate Path : " + cert_path)

        self.__common_service = CommonService(loopchain_pb2)
        self.__admin_manager = AdminManager("station")
        self.__channel_manager = None
        self.__rest_service = None
        self.__timer_service = TimerService()

        # RS has two status (active, standby) active means enable outer service
        # standby means stop outer service and heartbeat to the other RS (active)
        self.__is_active = False

        # 인증 클래스
        self.__ca = CertificateAuthorization()

        if cert_path is not None:
            # 인증서 로드
            self.__ca.load_pki(cert_path, cert_pass)

        logging.info("Current RadioStation SECURITY_MODE : " + str(self.__ca.is_secure))

        # gRPC service for Radiostation
        self.__outer_service = OuterService()
        self.__admin_service = AdminService(self.__admin_manager)

        # {group_id:[ {peer_id:IP} ] }로 구성된 dictionary
        self.peer_groups = {conf.ALL_GROUP_ID: []}

        # Peer의 보안을 담당
        self.auth = {}

        ObjectManager().rs_service = self

    def __del__(self):
        pass

    def launch_block_generator(self):
        pass

    @property
    def admin_manager(self):
        return self.__admin_manager

    @property
    def channel_manager(self):
        return self.__channel_manager

    @property
    def common_service(self):
        return self.__common_service

    @property
    def timer_service(self):
        return self.__timer_service

    def __broadcast_new_peer(self, peer_request):
        """새로 들어온 peer 를 기존의 peer 들에게 announce 한다."""

        logging.debug("Broadcast New Peer.... " + str(peer_request))
        if self.__channel_manager is not None:
            self.__channel_manager.broadcast(peer_request.channel, "AnnounceNewPeer", peer_request)

    def check_peer_status(self, channel):
        """service loop for status heartbeat check to peer list

        :return:
        """
        util.logger.spam(f"rs_service:check_peer_status(Heartbeat...{channel}) "
                         f"for reset Leader and delete no response Peer")

        peer_manager = self.__channel_manager.get_peer_manager(channel)
        nonresponse_peer_list = peer_manager.check_peer_status()
        logging.info(f"nonresponse_peer_list : {nonresponse_peer_list}")

        # save current peer_manager after heartbeat to peers.
        ObjectManager().rs_service.admin_manager.save_peer_manager(
            channel, peer_manager)

    def __create_random_table(self, rand_seed: int) -> list:
        """create random_table using random_seed
        table size define in conf.RANDOM_TABLE_SIZE

        :param rand_seed: random seed for create random table
        :return: random table
        """
        random.seed(rand_seed)
        random_table = []
        for i in range(conf.RANDOM_TABLE_SIZE):
            random_num: int = random.getrandbits(conf.RANDOM_SIZE)
            random_table.append(random_num)

        return random_table

    def register_peers(self):
        util.logger.spam(f"register_peers() : start register to peer_manager")

        logging.debug(f"register_peers() : channel_list = {self.admin_manager.get_channel_list()}")
        for channel_name, channel_data in self.admin_manager.json_data.items():
            peer_manager = self.channel_manager.get_peer_manager(channel_name)

            for peer_data in channel_data['peers']:
                peer_info = {
                    "id": peer_data['id'],
                    "peer_target": peer_data['peer_target'],
                    "order": peer_data['order']
                }
                logging.debug(f"register Peer : channel = {channel_name}, peer_info = {peer_info}")

                util.logger.spam(f"before load peer_manager "
                                 f"peer_count({peer_manager.get_peer_count()})")

                if peer_manager.get_peer_count() == 0:
                    util.logger.spam(f"try load peer_manager from db")
                    peer_manager = self.admin_manager.load_peer_manager(channel_name)
                    self.channel_manager.set_peer_manager(channel_name, peer_manager)

                util.logger.spam(f"after load peer_manager "
                                 f"peer_count({peer_manager.get_peer_count()})")

                peer_manager.add_peer(peer_info)

            # save current peer_manager after ConnectPeer from new peer.
            self.admin_manager.save_peer_manager(channel_name, peer_manager)

            if conf.ENABLE_RADIOSTATION_HEARTBEAT:
                timer_key = f"{TimerService.TIMER_KEY_RS_HEARTBEAT}_{channel_name}"
                if timer_key not in self.timer_service.timer_list:
                    self.timer_service.add_timer(
                        timer_key,
                        Timer(
                            target=timer_key,
                            duration=conf.SLEEP_SECONDS_IN_RADIOSTATION_HEARTBEAT,
                            is_repeat=True,
                            callback=self.check_peer_status,
                            callback_kwargs={"channel": channel_name}
                        )
                    )

    def serve(self, port=None, event_for_init: multiprocessing.Event=None):
        """Peer(BlockGenerator Peer) to RadioStation

        :param port: RadioStation Peer
        :param event_for_init:
        """
        if port is None:
            port = conf.PORT_RADIOSTATION
        stopwatch_start = timeit.default_timer()

        self.__channel_manager = ChannelManager(self.__common_service)

        self.register_peers()
    
        # TODO: Currently, some environments are failing to execute RestServiceRS without this sleep.
        # This sleep fixes current node's issue but we need to fix it right way by investigating.
        time.sleep(1)

        if conf.ENABLE_REST_SERVICE:
            self.__rest_service = RestServiceRS(int(port))

        loopchain_pb2_grpc.add_RadioStationServicer_to_server(self.__outer_service, self.__common_service.outer_server)
        loopchain_pb2_grpc.add_AdminServiceServicer_to_server(self.__admin_service, self.__common_service.inner_server)

        logging.info("Start Radio Station service at port: " + str(port))

        self.__common_service.start(port)
        self.__timer_service.start()

        stopwatch_duration = timeit.default_timer() - stopwatch_start
        logging.info(f"Start Radio Station service at port: {port} start duration({stopwatch_duration})")

        if event_for_init is not None:
            event_for_init.set()

        signal.signal(signal.SIGINT, self.close)
        signal.signal(signal.SIGTERM, self.close)

        # service 종료를 기다린다.
        self.__common_service.wait()
        self.__timer_service.wait()

        if self.__rest_service is not None:
            self.__rest_service.stop()

    def close(self, sig, frame):
        self.__common_service.stop()
        self.__timer_service.stop()
