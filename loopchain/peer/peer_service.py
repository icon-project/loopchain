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

import asyncio
import datetime
import getpass
import math
import multiprocessing
import signal
import timeit
from functools import partial
from typing import Tuple, cast

from loopchain.baseservice import CommonSubprocess, RestService
# FIXME : import directly
from loopchain.baseservice.lru_cache import lru_cache
from loopchain.blockchain import *
from loopchain.crypto.signature import Signer
from loopchain.p2p.bridge import PeerBridgeBase
from loopchain.p2p.p2p_service import P2PService
from loopchain.peer import PeerInnerService
from loopchain.peer.state_borg import PeerState
from loopchain.utils import loggers, command_arguments
from loopchain.utils.message_queue import StubCollection


class PeerInnerBridge(PeerBridgeBase):
    """ Implementation of PeerBridgeBase
    P2PService call function of ChannelService and using PeerState by this PeerBridge interface
    """

    def __init__(self, inner_service):
        self._inner_service = inner_service
        self._peer_state = PeerState()
        self._status_cache_update_time = {}

    def _status_update(self, channel_name, future):
        # update peer outer status cache by channel
        utils.logger.spam(f"status_update() channel({channel_name}) result({future.result()})")
        self._status_cache_update_time[channel_name] = datetime.datetime.now()
        self._peer_state.status_cache[channel_name] = future.result()

    @lru_cache(maxsize=1, valued_returns_only=True)
    def __get_status_cache(self, channel_name, time_in_seconds):
        """Cache status data.

        :param channel_name:
        :param time_in_seconds: An essential parameter for the `LRU cache` even if not used.

        :return:
        """
        try:
            channel_stub = StubCollection().channel_stubs[channel_name]
        except KeyError:
            from loopchain.blockchain import ChannelStatusError
            raise ChannelStatusError(f"Invalid channel({channel_name})")

        logging.warning(f"__get_status_cache() status_cache = {self._peer_state.status_cache}")
        if self._peer_state.status_cache.get(channel_name) is None:
            self._peer_state.status_cache[channel_name] = channel_stub.sync_task().get_status()
        else:
            future = asyncio.run_coroutine_threadsafe(
                channel_stub.async_task().get_status(),
                self._inner_service.loop)
            callback = partial(self._status_update, channel_name)
            future.add_done_callback(callback)

        return self._peer_state.status_cache.get(channel_name)

    def channel_get_status_data(self, channel_name: str, request: str) -> Dict:
        try:
            channel_stub = StubCollection().channel_stubs[channel_name]
        except KeyError:
            from loopchain.blockchain import ChannelStatusError
            raise ChannelStatusError(f"Invalid channel({channel_name})")

        status_data: Optional[dict] = None
        if request == 'block_sync':
            try:
                status_data = cast(dict, channel_stub.sync_task().get_status())
            except BaseException as e:
                utils.logger.error(f"Peer GetStatus(block_sync) Exception : {e}")
        else:
            status_data = self.__get_status_cache(channel_name,
                                                  time_in_seconds=math.trunc(time.time()))

        if status_data is None:
            from loopchain.blockchain import ChannelStatusError
            raise ChannelStatusError(f"Fail get status data from channel({channel_name})")

        return status_data

    def channel_mq_status_data(self, channel_name) -> Dict:
        stubs = {
            "peer": StubCollection().peer_stub,
            "channel": StubCollection().channel_stubs.get(channel_name),
            "score": StubCollection().icon_score_stubs.get(channel_name)
        }

        mq_status_data = {}
        for key, stub in stubs.items():
            message_count = -1
            message_error = None
            try:
                mq_info = stub.sync_info().queue_info()
                message_count = mq_info.method.message_count
            except AttributeError:
                message_error = "Stub is not initialized."
            except Exception as e:
                message_error = f"{type(e).__name__}, {e}"

            mq_status_data[key] = {}
            mq_status_data[key]["message_count"] = message_count
            if message_error:
                mq_status_data[key]["error"] = message_error

        return mq_status_data

    def channel_complain_leader(self, channel_name, complain_vote):
        channel_stub = StubCollection().channel_stubs[channel_name]
        asyncio.run_coroutine_threadsafe(
            channel_stub.async_task().complain_leader(vote_dumped=complain_vote),
            self._inner_service.loop
        )

    def channel_tx_receiver_add_tx_list(self, channel_name, request):
        StubCollection().channel_tx_receiver_stubs[channel_name].sync_task().add_tx_list(request)

    def channel_announce_unconfirmed_block(self, channel_name, block, round_):
        channel_stub = StubCollection().channel_stubs[channel_name]

        asyncio.run_coroutine_threadsafe(
            channel_stub.async_task().announce_unconfirmed_block(block, round_),
            self._inner_service.loop
        )

    def channel_block_sync(self, channel_name, block_hash, block_height) -> Tuple:
        channel_stub = StubCollection().channel_stubs[channel_name]
        future = asyncio.run_coroutine_threadsafe(
            channel_stub.async_task().block_sync(block_hash, block_height),
            self._inner_service.loop
        )
        return future.result()

    def channel_vote_unconfirmed_block(self, channel_name, vote_dumped):
        channel_stub = StubCollection().channel_stubs[channel_name]
        asyncio.run_coroutine_threadsafe(
            channel_stub.async_task().vote_unconfirmed_block(vote_dumped),
            self._inner_service.loop
        )


class PeerService:
    """Peer Service
    p2p networking with P2PService(outer) and inter process communication with rabbitMQ(inner)
    """
    def __init__(self):
        self._peer_state = PeerState()
        self.p2p_service: P2PService = None

        self._peer_state.peer_id = None
        self._peer_state.peer_port = 0
        self._peer_state.peer_target = None
        self._peer_state.rest_target = None
        self._peer_state.channel_infos = {}
        self._peer_state.node_keys = bytes()
        # peer status cache for channel
        self._peer_state.status_cache = {}

        # gRPC service for Peer
        self._inner_service: PeerInnerService = None

        self._channel_services = {}
        self._rest_service = None

        ObjectManager().peer_service = self

    @property
    def peer_target(self):
        return self._peer_state.peer_target

    @property
    def rest_target(self):
        return self._peer_state.reset_target

    @property
    def channel_infos(self):
        return self._peer_state.channel_infos

    @property
    def peer_port(self):
        return self._peer_state.peer_port

    @property
    def peer_id(self):
        return self._peer_state.peer_id

    @property
    def node_key(self):
        return self._peer_state.node_key

    def _init_port(self, port):
        # service 초기화 작업
        target_ip = utils.get_private_ip()
        self._peer_state.peer_target = f"{target_ip}:{port}"
        self._peer_state.peer_port = int(port)

        rest_port = int(port) + conf.PORT_DIFF_REST_SERVICE_CONTAINER
        self._peer_state.rest_target = f"{target_ip}:{rest_port}"

        logging.info("Start Peer Service at port: " + str(port))

    def _run_rest_services(self, port):
        if conf.ENABLE_REST_SERVICE and conf.RUN_ICON_IN_LAUNCHER:
            logging.debug(f'Launch Sanic RESTful server. '
                          f'Port = {int(port) + conf.PORT_DIFF_REST_SERVICE_CONTAINER}')
            self._rest_service = RestService(int(port))

    def _init_node_key(self):
        prikey_file = conf.PRIVATE_PATH

        if conf.PRIVATE_PASSWORD:
            password = conf.PRIVATE_PASSWORD
        else:
            password = getpass.getpass(f"Input your keystore password: ")
        signer = Signer.from_prikey_file(prikey_file, password)
        self._make_peer_id(signer.address)
        self._peer_state.node_key = signer.get_private_secret()

    def _make_peer_id(self, address):
        self._peer_state.peer_id = address

        logger_preset = loggers.get_preset()
        logger_preset.peer_id = self.peer_id
        logger_preset.update_logger()

        logging.info(f"run peer_id : {self._peer_state.peer_id}")

    @staticmethod
    def _get_use_kms():
        if conf.GRPC_SSL_KEY_LOAD_TYPE == conf.KeyLoadType.KMS_LOAD:
            return True
        for value in conf.CHANNEL_OPTION.values():
            if value["key_load_type"] == conf.KeyLoadType.KMS_LOAD:
                return True
        return False

    def _init_kms_helper(self, agent_pin):
        if self._get_use_kms():
            from loopchain.tools.kms_helper import KmsHelper
            KmsHelper().set_agent_pin(agent_pin)

    def _close_kms_helper(self):
        if self._get_use_kms():
            from loopchain.tools.kms_helper import KmsHelper
            KmsHelper().remove_agent_pin()

    def start_p2p_server(self):
        self.p2p_service.start_server()

    def stop_p2p_server(self):
        self.p2p_service.stop_server()

    def serve(self,
              port,
              agent_pin: str = None,
              amqp_target: str = None,
              amqp_key: str = None,
              event_for_init: multiprocessing.Event = None):
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

        self._init_kms_helper(agent_pin)
        self._init_port(port)
        self._init_node_key()

        StubCollection().amqp_target = amqp_target
        StubCollection().amqp_key = amqp_key

        peer_queue_name = conf.PEER_QUEUE_NAME_FORMAT.format(amqp_key=amqp_key)
        self._inner_service = PeerInnerService(
            amqp_target, peer_queue_name, conf.AMQP_USERNAME, conf.AMQP_PASSWORD)

        self._peer_state.channel_infos = conf.CHANNEL_OPTION

        self._run_rest_services(port)

        self.p2p_service = P2PService(self.peer_port, PeerInnerBridge(self._inner_service))
        self.start_p2p_server()

        self._close_kms_helper()

        stopwatch_duration = timeit.default_timer() - stopwatch_start
        logging.info(f"Start Peer Service at port: {port} start duration({stopwatch_duration})")

        async def _serve():
            await self.ready_tasks()
            await self._inner_service.connect(conf.AMQP_CONNECTION_ATTEMPTS, conf.AMQP_RETRY_DELAY, exclusive=True)

            if conf.CHANNEL_BUILTIN:
                await self.serve_channels()

            if event_for_init is not None:
                event_for_init.set()

            logging.info(f'peer_service: init complete peer: {self.peer_id}')

        loop = self._inner_service.loop
        loop.create_task(_serve())
        loop.add_signal_handler(signal.SIGINT, self.close)
        loop.add_signal_handler(signal.SIGTERM, self.close)

        try:
            loop.run_forever()
        finally:
            loop.run_until_complete(loop.shutdown_asyncgens())
            self._cleanup(loop)
            loop.close()

        logging.info("Peer Service Ended.")

    def close(self):
        self._inner_service.loop.stop()

    def _cleanup(self, loop):
        logging.info("_cleanup() Peer Resources.")
        for task in asyncio.Task.all_tasks(loop):
            if task.done():
                continue
            task.cancel()
            try:
                loop.run_until_complete(task)
            except asyncio.CancelledError as e:
                logging.info(f"_cleanup() task : {task}, error : {e}")

        self.stop_p2p_server()
        logging.info("_cleanup() p2p server.")

        if self._rest_service is not None:
            self._rest_service.stop()
            self._rest_service.wait()
            logging.info("_cleanup() Rest Service.")

    async def serve_channels(self):
        for i, channel_name in enumerate(self.channel_infos):
            score_port = (self._peer_state.peer_port
                          + conf.PORT_DIFF_SCORE_CONTAINER
                          + conf.PORT_DIFF_BETWEEN_SCORE_CONTAINER * i)

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

            self._channel_services[channel_name] = service

    async def ready_tasks(self):
        await StubCollection().create_peer_stub()  # for getting status info

        for channel_name in self.channel_infos:
            await StubCollection().create_channel_stub(channel_name)
            await StubCollection().create_channel_tx_receiver_stub(channel_name)

            await StubCollection().create_icon_score_stub(channel_name)
