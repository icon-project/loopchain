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

from enum import Enum
from loopchain import configure as conf
from loopchain.utils.loggers.configuration import LogConfiguration


develop = LogConfiguration()
develop.log_format = conf.LOG_FORMAT
develop.log_color = True

production = LogConfiguration()
production.log_format = conf.LOG_FORMAT
production.log_color = False


class PresetType(Enum):
    develop = 0
    production = 1


_preset_type = PresetType.production
_presets = {
    PresetType.develop: develop,
    PresetType.production: production
}


def get_preset_type():
    return _preset_type


def set_preset_type(preset):
    global _preset_type
    _preset_type = preset


def get_preset():
    return _presets[_preset_type]


def get_presets():
    return _presets


def set_presets(presets: dict):
    global develop
    global production
    for key, value in presets.items():
        if key == PresetType.develop:
            develop = value
        elif key == PresetType.production:
            production = value
        _presets[key] = value


def update_preset(update_logger=True):
    preset = get_preset()

    preset.log_format = conf.LOG_FORMAT
    preset.log_output_type = conf.LOG_OUTPUT_TYPE

    preset.log_file_location = conf.LOG_FILE_LOCATION
    preset.log_file_prefix = conf.LOG_FILE_PREFIX
    preset.log_file_extension = conf.LOG_FILE_EXTENSION
    preset.log_file_rotate_backup_count = conf.LOG_FILE_ROTATE_BACKUP_COUNT
    preset.log_file_rotate_interval = conf.LOG_FILE_ROTATE_INTERVAL
    preset.log_file_rotate_max_bytes = conf.LOG_FILE_ROTATE_MAX_BYTES
    preset.log_file_rotate_utf = conf.LOG_FILE_ROTATE_UTC
    preset.log_file_rotate_when = conf.LOG_FILE_ROTATE_WHEN

    preset.log_monitor = conf.MONITOR_LOG
    preset.log_monitor_host = conf.MONITOR_LOG_HOST
    preset.log_monitor_port = conf.MONITOR_LOG_PORT

    if preset is develop:
        preset.log_level = conf.LOOPCHAIN_DEVELOP_LOG_LEVEL
    else:
        preset.log_level = conf.LOOPCHAIN_LOG_LEVEL

    if update_logger:
        preset.update_logger()
