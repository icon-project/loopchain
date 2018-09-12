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
"""Base Classes for Loopchain Plugin
"""

import abc
import importlib
import logging
from enum import IntEnum

from loopchain import configure as conf
from loopchain.components import SingletonMetaClass


class PluginReturns(IntEnum):
    CONTINUE = 0


class LoopchainScorePlugin(abc.ABC):
    @abc.abstractmethod
    def genesis_invoke(self, **kwargs):
        raise NotImplementedError("'genesis_invoke' is not implemented.")

    @abc.abstractmethod
    def invoke(self, **kwargs):
        raise NotImplementedError("'invoke' is not implemented.")

    @abc.abstractmethod
    def query(self, **kwargs):
        raise NotImplementedError("'query' is not implemented.")


class LoopchainIISSPlugin(abc.ABC):
    @abc.abstractmethod
    def after_invoke(self, **kwargs):
        raise NotImplementedError("'after_invoke is not implemented.")


class DefaultLoopchainScorePlugin(LoopchainScorePlugin):
    def genesis_invoke(self, **kwargs):
        return PluginReturns.CONTINUE

    def invoke(self, **kwargs):
        return PluginReturns.CONTINUE

    def query(self, **kwargs):
        return PluginReturns.CONTINUE


class DefaultLoopchainIISSPlugin(LoopchainIISSPlugin):
    def after_invoke(self, **kwargs):
        return PluginReturns.CONTINUE


class Plugins(metaclass=SingletonMetaClass):
    """load plugins for loopchain

    """
    default_plugins = {
        LoopchainScorePlugin: DefaultLoopchainScorePlugin,
        LoopchainIISSPlugin: DefaultLoopchainIISSPlugin
    }

    def __load_plugin(self, channel, plugin_type):
        try:
            plugins = conf.CHANNEL_OPTION[channel]["plugins"]
            logging.debug(f"Plugins:__load_plugin ({plugins})")
        except KeyError as e:
            logging.debug(f"Plugins:__load_plugin there is no plugin ({e})")
            plugins = []

        for plugin_name in plugins:
            splitter = plugin_name.rindex(".") if "." in plugin_name else 0
            package_name, class_name = plugin_name[:splitter], plugin_name[splitter + 1:]

            mod = importlib.import_module(package_name)
            cls = getattr(mod, class_name)

            if issubclass(cls, plugin_type):
                logging.debug(f"load score plugin from ({package_name}) import ({class_name})")
                return cls()

        return self.default_plugins[plugin_type]()

    def load_score_plugin(self, channel):
        return self.__load_plugin(channel, LoopchainScorePlugin)

    def load_iiss_plugin(self, channel):
        return self.__load_plugin(channel, LoopchainIISSPlugin)
