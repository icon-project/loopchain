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
""" A class for Manage Channels """
import logging

from loopchain import configure as conf
from loopchain.baseservice import BroadcastSchedulerFactory, BroadcastCommand, PeerManager, ObjectManager
from loopchain.container import CommonService


class ChannelManager:
    """어떤 Peer가 loopchain network 에 접속할 권한을 가지고 있는지 어떤 채널에 속할 권한을 가지고 있는지 관리한다.
    이 데이터는 RS Admin site 를 통해서 설정될 수 있으며, 이중화 또는 3중화된 복수의 RS가 존재할 경우 이 데이터를 동기되어야한다.
    key 생성을 위한 난수표는 메모리상에만 존재해야 하며 나머지 데이터는 level DB 를 사용한다.
    """

    def __init__(self, common_service: CommonService):
        self.__common_service = common_service
        self.__peer_managers = {}  # key(channel_name):value(peer_manager)
        self.__broadcast_schedulers = {}  # key(channel_name):value(broadcast_thread)
        self.__init_rs_channel_manager()

    def __init_rs_channel_manager(self):
        for channel in ObjectManager().rs_service.admin_manager.get_channel_list():
            self.__load_peer_manager(channel)
            self.__start_broadcast_scheduler(channel)

    def __load_peer_manager(self, channel=None):
        """leveldb 로 부터 peer_manager 를 가져온다.

        :return: peer_manager
        """

        if channel is None:
            channel = conf.LOOPCHAIN_DEFAULT_CHANNEL
        peer_manager = PeerManager(channel, )
        self.__peer_managers[channel] = peer_manager

    def __start_broadcast_scheduler(self, channel):
        scheduler = BroadcastSchedulerFactory.new(channel=channel)
        scheduler.start()

        self.__broadcast_schedulers[channel] = scheduler
        return scheduler

    def get_channel_list(self) -> list:
        return list(self.__peer_managers)

    def get_channel_option(self, channel) -> dict:
        return conf.CHANNEL_OPTION[channel]

    def get_peer_manager(self, channel_name=None) -> PeerManager:
        if channel_name is None:
            channel_name = conf.LOOPCHAIN_DEFAULT_CHANNEL
        return self.__peer_managers[channel_name]

    def set_peer_manager(self, channel, peer_manager):
        self.__peer_managers[channel] = peer_manager

    def add_audience(self, channel: str, peer_target: str):
        if channel in self.__broadcast_schedulers.keys():
            self.__broadcast_schedulers[channel].schedule_job(BroadcastCommand.SUBSCRIBE, peer_target)
        else:
            logging.debug(f"channel_manager:add_audience no channel({channel}) in broadcast_threads")

    def remove_audience(self, channel, peer_target):
        if channel in self.__broadcast_schedulers.keys():
            self.__broadcast_schedulers[channel].schedule_job(BroadcastCommand.UNSUBSCRIBE, peer_target)
        else:
            logging.debug(f"channel_manager:remove_audience no channel({channel}) in broadcast_threads")

    def update_audience(self, channel, peer_manager_dump):
        if channel in self.__broadcast_schedulers.keys():
            self.__broadcast_schedulers[channel].schedule_job(
                BroadcastCommand.UPDATE_AUDIENCE, peer_manager_dump)
        else:
            logging.debug(f"channel_manager:update_audience no channel({channel}) in broadcast_threads")

    def broadcast(self, channel, method_name, method_param, response_handler=None, *, retry_times=None, timeout=None):
        """등록된 모든 Peer 의 동일한 gRPC method 를 같은 파라미터로 호출한다.
        """
        # logging.warning("broadcast in process ==========================")
        # logging.debug("pickle method_param: " + str(pickle.dumps(method_param)))

        if channel in self.__broadcast_schedulers.keys():
            kwargs = {}
            if retry_times:
                kwargs['retry_times'] = retry_times

            if timeout:
                kwargs['timeout'] = timeout

            self.__broadcast_schedulers[channel].schedule_job(
                BroadcastCommand.BROADCAST, (method_name, method_param, kwargs))
        else:
            logging.debug(f"channel_manager:broadcast no channel({channel}) in broadcast_threads")

    def authorized_channels(self, peer_id) -> list:
        authorized_channels = []

        for channel in list(self.__peer_managers):
            logging.warning(f"channel is ({channel})")
            authorized_channels.append(channel)

        logging.warning(f"authorized channels ({authorized_channels})")

        return authorized_channels
