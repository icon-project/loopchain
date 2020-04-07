# Copyright 2019 ICON Foundation
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

import threading
import multiprocessing as mp
import logging
import os
import signal

from loopchain import configure as conf
from loopchain.utils import loggers


class ModuleProcessProperties:
    def __init__(self):
        self.configurations = conf.get_origin_type_configurations()
        self.logger_preset_type = loggers.get_preset_type()
        self.logger_presets = loggers.get_presets()


class ModuleProcess:
    def __init__(self):
        self.__context: mp.context.SpawnContext = mp.get_context('spawn')

        self.__process: mp.Process = None
        self.__process_pid = None
        self.__terminated_lock = threading.Lock()
        self.__join_thread: threading.Thread = None

    def __repr__(self):
        return f"{self.__process_pid}:{self.__class__.__qualname__}({hex(id(self))})"

    def Queue(self, maxsize=0) -> mp.Queue:
        return self.__context.Queue(maxsize=maxsize)

    @staticmethod
    def load_properties(properties: ModuleProcessProperties, module_name):
        conf.set_origin_type_configurations(properties.configurations)

        loggers.set_preset_type(properties.logger_preset_type)
        loggers.update_other_loggers()

        loggers.set_presets(properties.logger_presets)
        preset = loggers.get_preset()
        if preset.service_type:
            preset.service_type += f"-{module_name}"
        else:
            preset.service_type = module_name
        preset.update_logger()

    def start(self, target, args=(), crash_callback_in_join_thread=None):
        if self.__process is not None:
            raise RuntimeError(f"Process({self}) has already been started")

        properties = ModuleProcessProperties()

        self.__process: mp.Process = self.__context.Process(target=target, args=args, kwargs={'properties': properties})
        self.__process.start()
        self.__process_pid = self.__process.pid

        def _join_process():
            self.__process.join()
            logging.info(f"Process({self}) is terminated")

            with self.__terminated_lock:
                if self.__process is None:
                    return
                logging.error(f"Process({self}) crash occurred")
                self.__process = None

            if crash_callback_in_join_thread is not None:
                crash_callback_in_join_thread(self)

        self.__join_thread: threading.Thread = threading.Thread(target=_join_process)
        self.__join_thread.start()

    def terminate(self):
        with self.__terminated_lock:
            if self.__process is not None:
                logging.info(f"Terminate process={self}")
                self.__process.terminate()
                self.__process: mp.Process = None

    def join(self):
        if self.__join_thread is None:
            raise RuntimeError(f"Process({self}) has not been started yet")

        self.__join_thread.join(timeout=conf.SUB_PROCESS_JOIN_TIMEOUT)

        if self.__join_thread.is_alive():
            logging.error(f"timeout to join process({self})")
            os.kill(self.__process_pid, signal.SIGKILL)
            self.__join_thread.join(timeout=conf.SUB_PROCESS_JOIN_TIMEOUT)

        self.__join_thread: threading.Thread = None
