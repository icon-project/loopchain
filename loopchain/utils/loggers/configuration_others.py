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

import logging
from loopchain import configure as conf
from loopchain.utils.loggers.configuration import LogConfiguration
from loopchain.utils.loggers.configuration_presets import PresetType, get_preset_type

preset_others = LogConfiguration()


def update_other_loggers():
    preset_others.log_monitor = conf.MONITOR_LOG
    preset_others.log_monitor_host = conf.MONITOR_LOG_HOST
    preset_others.log_monitor_port = conf.MONITOR_LOG_PORT

    if get_preset_type() == PresetType.develop:
        preset_others.log_level = logging.WARNING
        preset_others.log_color = True
    else:
        preset_others.log_level = conf.LOOPCHAIN_OTHER_LOG_LEVEL
        preset_others.log_color = False

    logger_pika = logging.getLogger('pika')
    preset_others.update_logger(logger_pika)

    logger_aio_pika = logging.getLogger('aio_pika')
    preset_others.update_logger(logger_aio_pika)

    logger_json_rpc_client_request = logging.getLogger('jsonrpcclient.client.request')
    preset_others.update_logger(logger_json_rpc_client_request)

    logger_json_rpc_client_response = logging.getLogger('jsonrpcclient.client.response')
    preset_others.update_logger(logger_json_rpc_client_response)

    preset_others.log_level = logging.ERROR  # force setting
    logger_sanic_access = logging.getLogger('sanic.access')
    preset_others.update_logger(logger_sanic_access)

    logger_websockets = logging.getLogger('websockets')
    preset_others.update_logger(logger_websockets)
