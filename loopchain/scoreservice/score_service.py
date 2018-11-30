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

# This file is obsolete.

""" A class for gRPC service of Score service"""

import logging
import setproctitle
import timeit

from typing import TYPE_CHECKING
from loopchain import configure as conf
from loopchain.baseservice.plugin_bases import Plugins
from loopchain.scoreservice import ScoreInnerService
from loopchain.tools.score_helper import ScoreHelper
from loopchain.utils import loggers
from loopchain.utils.message_queue import StubCollection


if TYPE_CHECKING:
    from loopchain.baseservice import PeerScore


class ScoreService:
    """Score service for stand alone start. It has gRPC interface for peer_service can invoke and query to score.
    """

    def __init__(self, channel, score_package, amqp_target, amqp_key):
        """Score service init
        """
        loggers.get_preset().channel_name = channel
        loggers.get_preset().score_package = score_package
        loggers.get_preset().update_logger()
        loggers.update_other_loggers()

        self.score: PeerScore = None
        self.score_plugin = Plugins().load_score_plugin(channel)
        self.iiss_plugin = Plugins().load_iiss_plugin(channel)

        self.__peer_id: str = None
        self.__channel_name: str = channel

        StubCollection().amqp_key = amqp_key
        StubCollection().amqp_target = amqp_target

        score_queue_name = conf.SCORE_QUEUE_NAME_FORMAT.format(
            score_package_name=score_package, channel_name=channel, amqp_key=amqp_key)
        self.__inner_service = ScoreInnerService(
            amqp_target, score_queue_name, conf.AMQP_USERNAME, conf.AMQP_PASSWORD, score_service=self)

        setproctitle.setproctitle(f"{setproctitle.getproctitle()} {channel}")

    @property
    def channel_name(self):
        return self.__channel_name

    @property
    def peer_id(self):
        return self.__peer_id

    @peer_id.setter
    def peer_id(self, value):
        self.__peer_id = ScoreHelper().peer_id = value

    def service_stop(self):
        self.__inner_service.loop.stop()

    def serve(self):
        stopwatch_start = timeit.default_timer()

        stopwatch_duration = timeit.default_timer() - stopwatch_start
        logging.info(f"Start Score Service start duration({stopwatch_duration})")

        self.__inner_service.serve(
            exclusive=True,
            connection_attempts=conf.AMQP_CONNECTION_ATTEMPS,
            retry_delay=conf.AMQP_RETRY_DELAY)
        self.__inner_service.serve_all()
        self.__inner_service.loop.close()
