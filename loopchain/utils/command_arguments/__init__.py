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

from argparse import Namespace
from enum import IntEnum
from typing import Dict


class Type(IntEnum):
    ServiceType = 0
    Port = 1
    ConfigurationFilePath = 2
    RadioStationTarget = 3
    Develop = 4
    AgentPin = 5
    Cert = 6
    Seed = 7
    Channel = 8
    AMQPTarget = 9
    AMQPKey = 10
    Version = 11
    Rollback = 12


class Attribute:
    def __init__(self, *names, **kwargs):
        self.names = names
        self.kwargs = kwargs

    def command(self, value):
        if value is None or value is False:
            return []

        if value is '' or value is True:
            return [self.names[0]]

        if self.names[0][0] != '-':
            return [str(value)]

        return [self.names[0], str(value)]


types_by_names = {
    "service_type": Type.ServiceType,
    "port": Type.Port,
    "configure_file_path": Type.ConfigurationFilePath,
    "radio_station_target": Type.RadioStationTarget,
    "develop": Type.Develop,
    "agent_pin": Type.AgentPin,
    "cert": Type.Cert,
    "seed": Type.Seed,
    "channel": Type.Channel,
    "amqp_target": Type.AMQPTarget,
    "amqp_key": Type.AMQPKey,
    "version": Type.Version,
    "rollback": Type.Rollback

}

attributes = {
    Type.ServiceType:
        Attribute("service_type", type=str, default='citizen', nargs='?',
                  help="loopchain service to start [peer|citizen|tool|admin]"),

    Type.Port:
        Attribute("-p", "--port",
                  help="port of Service itself"),

    Type.ConfigurationFilePath:
        Attribute("-o", "--configure_file_path",
                  help="json configure file path"),

    # options for peer
    # r, rs, radiostation means higher layer node.
    Type.RadioStationTarget:
        Attribute("-r", "--radio_station_target",
                  help="[IP Address of Radio Station]:[PORT number of Radio Station], "
                       "[IP Address of Sub Radio Station]:[PORT number of Sub Radio Station] "
                       "or just [IP Address of Radio Station]"),
    Type.Develop:
        Attribute("-d", "--develop", action="store_true",
                  help="develop mode(log level, etc)"),

    Type.AgentPin:
        Attribute("-a", "--agent_pin",
                  help="kms agent pin for kms load"),

    # options for radiostation
    Type.Cert:
        Attribute("--cert",
                  help="certificate directory path"),

    Type.Seed:
        Attribute("-s", "--seed",
                  help="create random table seed for KMS"),

    # options for score service
    Type.Channel:
        Attribute("--channel",
                  help="channel name for score service"),

    Type.AMQPTarget:
        Attribute("--amqp_target",
                  help="amqp target info [IP]:[PORT]"),

    Type.AMQPKey:
        Attribute("--amqp_key",
                  help="key sharing peer group using queue name. use it if one more peers connect one MQ"),

    Type.Version:
        Attribute("--version", action='store_true',
                  help="show version of loopchain and it's dependencies"),

    Type.Rollback:
        Attribute("--rollback", action='store_true',
                  help="rollback behind to 1 block(max 10 blocks is possible to rollback")
}

command_values: Dict[Type, str] = {}


def set_raw_commands(args: Namespace):
    command_values.clear()

    for arg_name, arg_value in args._get_kwargs():
        if arg_value:
            arg_type = types_by_names[arg_name]
            command_values[arg_type] = arg_value


def add_raw_command(arg_type, arg_value):
    command_values[arg_type] = arg_value


def get_raw_commands_by_filter(*filter_: Type):
    if len(filter_) == 0:
        filter_ = [type_ for type_ in Type]

    commands = []
    for type_, command_value in sorted(command_values.items()):
        if type_ in filter_:
            commands += attributes[type_].command(command_value)

    return commands
