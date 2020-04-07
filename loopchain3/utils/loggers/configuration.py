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
import logging.handlers
import coloredlogs
import verboselogs
import os
import sys
import traceback

from functools import partial, reduce
from operator import or_
from fluent import sender
from loopchain import configure as conf
from .sized_timed_file_handler import SizedTimedRotatingFileHandler


class LogConfiguration:
    def __init__(self):
        self.log_format = None
        self.service_type = ""
        self.peer_id = ""
        self.channel_name = ""
        self.log_level = verboselogs.SPAM
        self.log_color = True
        self.log_output_type = conf.LogOutputType.console
        self.log_file_location = ""
        self.log_file_prefix = ""
        self.log_file_extension = ""
        self.log_file_rotate_when = 'midnight'
        self.log_file_rotate_interval = 0
        self.log_file_rotate_max_bytes = 0
        self.log_file_rotate_backup_count = 0
        self.log_file_rotate_utf = False
        self.log_monitor = False
        self.log_monitor_host = None
        self.log_monitor_port = None
        self.is_leader = False

        self._log_level = None
        self._log_format = None
        self._log_file_path = None

    def update_logger(self, logger: logging.Logger=None):
        if logger is None:
            logger = logging.root

        self._log_level = self.log_level if isinstance(self.log_level, int) else logging.getLevelName(self.log_level)

        if logger is logging.root:
            self._log_format = self.log_format.format(
                PEER_ID=self.peer_id[:8] if self.peer_id != "RadioStation" else self.peer_id,
                CHANNEL_NAME=self.channel_name
            )

            self._update_log_output_type()
            self._update_handlers(logger)

            if self.log_color:
                self._update_log_color_set(logger)
                for handler in logger.handlers:
                    if isinstance(handler, logging.StreamHandler):
                        handler.addFilter(self._root_stream_filter)
        else:
            logger.setLevel(self._log_level)

        if self.log_monitor:
            sender.setup('loopchain', host=self.log_monitor_host, port=self.log_monitor_port)

    def _update_log_color_set(self, logger):
        # level SPAM value is 5
        # level DEBUG value is 10
        coloredlogs.DEFAULT_FIELD_STYLES = {
            'hostname': {'color': 'magenta'},
            'programname': {'color': 'cyan'},
            'name': {'color': 'blue'},
            'levelname': {'color': 'black', 'bold': True},
            'asctime': {'color': 'magenta'}}

        if self.is_leader:
            coloredlogs.DEFAULT_LEVEL_STYLES = {
                'info': {},
                'notice': {'color': 'magenta'},
                'verbose': {'color': 'green'},
                'success': {'color': 'green', 'bold': True},
                'spam': {'color': 'cyan'},
                'critical': {'color': 'red', 'bold': True},
                'error': {'color': 'red'},
                'debug': {'color': 'blue'},
                'warning': {'color': 'yellow'}}
        else:
            coloredlogs.DEFAULT_LEVEL_STYLES = {
                'info': {},
                'notice': {'color': 'magenta'},
                'verbose': {'color': 'blue'},
                'success': {'color': 'green', 'bold': True},
                'spam': {'color': 'cyan'},
                'critical': {'color': 'red', 'bold': True},
                'error': {'color': 'red'},
                'debug': {'color': 'green'},
                'warning': {'color': 'yellow'}}

        coloredlogs.install(logger=logger,
                            fmt=self._log_format,
                            datefmt="%Y-%m-%d %H:%M:%S",
                            level=self._log_level)

    def _update_log_file_path(self):
        log_file_name = self.log_file_prefix + "{SERVICE_TYPE}{CHANNEL_NAME}"
        log_file_name = log_file_name.format(
            SERVICE_TYPE=self.service_type and f".{self.service_type}",
            CHANNEL_NAME=self.channel_name and f".{self.channel_name}"
        ).replace(r"/", r"_")
        log_file_name += f".{self.log_file_extension}"

        self._log_file_path = os.path.join(self.log_file_location, log_file_name)

    def _update_log_output_type(self):
        if isinstance(self.log_output_type, str):
            self.log_output_type = reduce(
                or_,
                (conf.LogOutputType[flag.lower()] for flag in self.log_output_type.split('|')))

    def _update_handlers(self, logger):
        logging._acquireLock()
        try:
            for handler in logger.handlers[:]:
                logger.removeHandler(handler)

            handlers = []

            partial_new_excepthook = new_excepthook
            partial_new_print_exception = new_print_exception

            if self.log_output_type & conf.LogOutputType.console:
                stream_handler = self._create_stream_handler()
                handlers.append(stream_handler)

                partial_new_excepthook = partial(partial_new_excepthook, console=True)
                partial_new_print_exception = partial(partial_new_print_exception, console=True)
            else:
                partial_new_excepthook = partial(partial_new_excepthook, console=False)
                partial_new_print_exception = partial(partial_new_print_exception, console=False)

            if self.log_output_type & conf.LogOutputType.file and self.log_file_location:
                self._update_log_file_path()

                file_handler = self._create_file_handler()
                handlers.append(file_handler)

                sys.excepthook = partial(partial_new_excepthook, output_file=file_handler.stream)
                traceback.print_exception = partial(partial_new_print_exception, output_file=file_handler.stream)
            else:
                sys.excepthook = partial(partial_new_excepthook, output_file=None)
                traceback.print_exception = partial(partial_new_print_exception, output_file=None)

            logging.basicConfig(handlers=handlers,
                                format=self._log_format,
                                datefmt="%Y-%m-%d %H:%M:%S",
                                level=self._log_level)
        finally:
            logging._releaseLock()

    def _create_file_handler(self):
        if os.path.exists(self.log_file_location):
            if not os.path.isdir(self.log_file_location):
                raise RuntimeError(f"LogFileLocation({self.log_file_location}) is not a directory.")
        else:
            os.makedirs(self.log_file_location, exist_ok=True)

        if self.log_file_rotate_when and self.log_file_rotate_max_bytes:
            file_handler = SizedTimedRotatingFileHandler(
                self._log_file_path,
                max_bytes=self.log_file_rotate_max_bytes,
                when=self.log_file_rotate_when,
                interval=self.log_file_rotate_interval,
                backup_count=self.log_file_rotate_backup_count,
                utc=self.log_file_rotate_utf,
                encoding='utf-8',
                delay=False)
        elif self.log_file_rotate_when:
            file_handler = logging.handlers.TimedRotatingFileHandler(
                self._log_file_path,
                when=self.log_file_rotate_when,
                interval=self.log_file_rotate_interval,
                backupCount=self.log_file_rotate_backup_count,
                encoding='utf-8',
                delay=False,
                utc=self.log_file_rotate_utf
            )
        elif self.log_file_rotate_max_bytes:
            file_handler = logging.handlers.RotatingFileHandler(
                self._log_file_path,
                maxBytes=self.log_file_rotate_max_bytes,
                backupCount=self.log_file_rotate_backup_count,
                encoding='utf-8',
                delay=False
            )
        else:
            file_handler = logging.FileHandler(
                self._log_file_path,
                encoding='utf-8',
                delay=False
            )
        file_handler.level = self._log_level
        return file_handler

    def _create_stream_handler(self):
        stream_handler = logging.StreamHandler()
        stream_handler.level = self._log_level
        stream_handler.addFilter(self._root_stream_filter)
        return stream_handler

    def _root_stream_filter(self, record: logging.LogRecord):
        return record.name not in useless_streams


useless_streams = {
    "sanic.access"
}

tb_print_exception = traceback.print_exception
sys_excepthook = sys.excepthook


def new_print_exception(etype, value, tb, limit=None, file=None, chain=True, output_file=None, console=True):
    if file is None:
        file = sys.stderr

    if file is not sys.stderr or console:
        tb_print_exception(etype, value, tb, limit=limit, file=file, chain=chain)

    if output_file:
        tb_print_exception(etype, value, tb, limit=limit, file=output_file, chain=chain)


def new_excepthook(exc_type, exc_value, tb, output_file, console):
    if console:
        sys_excepthook(exc_type, exc_value, tb)

    if output_file:
        tb_print_exception(exc_type, exc_value, tb, file=output_file)
