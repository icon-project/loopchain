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
""" A module for configuration"""

import copy
import importlib
import json
import logging
import re
import pkg_resources

import loopchain
from loopchain.components.singleton import SingletonMetaClass
from loopchain.configure_default import *


class DataType(IntEnum):
    string = 0
    int = 1
    float = 2
    bool = 3
    dict = 4


class Configure(metaclass=SingletonMetaClass):

    def __init__(self):
        self.__configure_info_list = {}
        self.init_configure()

    def init_configure(self):
        # print("Set Configure... only once in scope from system environment.")
        # configure_info_list = {configure_attr: configure_type}
        self.__configure_info_list = {}
        self.__load_configure(loopchain.configure_default, use_env=True)
        self._set_package_version()

    @property
    def configure_info_list(self):
        return self.__configure_info_list

    def load_configure_json(self, configure_file_path: str) -> None:
        """method for reading and applying json configuration.

        :param configure_file_path: json configure file path
        :return: None
        """
        logging.debug(f"try load configure from json file ({configure_file_path})")

        try:
            with open(configure_file_path) as json_file:
                json_data = json.load(json_file)

            for configure_key, configure_value in json_data.items():
                try:
                    configure_type, configure_value = self.__check_value_type(type(configure_value), configure_value)
                    self.__set_configure(configure_key, configure_type, configure_value)
                except Exception as e:
                    # no configure value
                    logging.debug(f"this is not configure key({configure_key}): {e}")

        except Exception as e:
            exit(f"cannot open json file in ({configure_file_path}): {e}")

        importlib.reload(loopchain.utils)

    def __load_configure(self, module, use_env):
        configure_names = dir(module)

        for configure_name in configure_names:
            try:
                module_value = getattr(module, configure_name)
                if use_env:
                    env_value = os.getenv(configure_name, module_value)
                    configure_type, configure_value = self.__check_value_type(type(module_value), env_value)
                else:
                    configure_type, configure_value = self.__check_value_type(type(module_value), module_value)
                self.__set_configure(configure_name, configure_type, configure_value)
            except Exception as e:
                # no configure value
                logging.debug(f"this is not configure key({configure_name}): {e}")

    def __set_configure(self, configure_attr, configure_type, configure_value):
        if configure_attr.find('__') == -1 and configure_type is not None:
            globals()[configure_attr] = configure_value
            self.__configure_info_list[configure_attr] = configure_type

    def __check_value_type(self, target_value_type, value):
        # record type of configurations for managing in Configure class.
        target_value = self.__check_value_condition(target_value_type, value)

        # requirement: bool must be checked earlier than int.
        # If not, all of int and bool will be checked as int.
        if isinstance(target_value, bool):
            configure_type = DataType.bool
        elif isinstance(target_value, float):
            configure_type = DataType.float
        elif isinstance(target_value, str):
            configure_type = DataType.string
        elif isinstance(target_value, int):
            configure_type = DataType.int
        elif isinstance(target_value, dict):
            configure_type = DataType.dict
        else:
            configure_type = None

            # checking for environment variable of system
        return configure_type, target_value

    def __check_value_condition(self, target_value_type, value):
        # turn configure value to int or float after some condition check.
        # cast type string to original type if it exists in the globals().
        target_value = value
        if (isinstance(value, str) and len(value) > 0
                and target_value_type is not str):
            if re.match("^\d+?\.\d+?$", value) is not None:
                # print("float configure value")
                try:
                    target_value = float(value)
                except Exception as e:
                    print(f"this value can't convert to float! {value}: {e}")
            elif value.isnumeric():
                target_value = int(value)

        return target_value

    def __change_enum_to_int(self, dict_data):
        for key, value in copy.copy(dict_data).items():
            if isinstance(value, IntEnum):
                dict_data[key] = value.value
            elif isinstance(value, dict):
                self.__change_enum_to_int(value)

    def _set_package_version(self):
        icon_versions: dict = globals()['ICON_VERSIONS']
        for pkg_name in icon_versions.keys() - {'icon_rc'}:
            try:
                version = pkg_resources.get_distribution(pkg_name).version
                icon_versions[pkg_name] = version
            except pkg_resources.DistributionNotFound as e:
                logging.warning(f"get '{pkg_name}' version error : {e}")
                continue

        command_result = os.popen('icon_rc -version').read()
        match_result = re.match(r'([a-z_]+)\s([\da-zA-Z-_\.]+)', command_result)  # ('icon_rc', 'vX.X.X')
        if match_result:
            icon_rc_version = match_result.group(2)
            icon_versions['icon_rc'] = icon_rc_version


def get_configuration(configure_name):
    if configure_name in globals():
        return {
            'name': configure_name,
            'value': str(globals()[configure_name]),
            'type': Configure().configure_info_list[configure_name]
        }
    else:
        return None


def set_configuration(configure_name, configure_value):
    if configure_name in globals():
        globals()[configure_name] = configure_value
        return True
    else:
        return False


def get_all_configurations():
    rs_configuration_list = []

    for configuration_key in Configure().configure_info_list.keys():
        rs_configuration_list.append({
            'name': configuration_key,
            'value': str(globals()[configuration_key]),
            'type': Configure().configure_info_list[configuration_key]
        })

    return rs_configuration_list


def set_origin_type_configurations(configurations: dict):
    for key, value in configurations.items():
        set_configuration(key, value)


def get_origin_type_configurations():
    configurations = dict()
    for key in Configure().configure_info_list:
        configurations[key] = globals()[key]
    return configurations


Configure()
