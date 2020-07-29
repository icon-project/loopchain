#!/usr/bin/env python
# -*- coding: utf-8 -*-

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

import argparse
import json
import logging
import time

from loopchain import configure as conf
from loopchain import utils
from loopchain.channel.channel_service import ChannelService
from loopchain.peer import PeerService
from loopchain.tools.grpc_helper import grpc_patcher
from loopchain.utils import loggers, command_arguments, async_


def parse_args_include_unknowns(parser, args=None, namespace=None):
    args, argv = parser.parse_known_args(args, namespace)
    unknowns = None
    if argv:
        print(f'unrecognized arguments: {argv}')
        unknowns = ''.join(argv)
    return args, unknowns


def get_quick_command(unknowns):
    if not unknowns:
        return None

    quick_command = ''.join(unknowns.split('-'))
    if quick_command.isnumeric():
        return unknowns

    raise Exception(f'There is unrecognized argument {unknowns}')


def main(argv):
    parser = argparse.ArgumentParser()
    for cmd_arg_type in command_arguments.Type:
        cmd_arg_attr = command_arguments.attributes[cmd_arg_type]
        parser.add_argument(*cmd_arg_attr.names, **cmd_arg_attr.kwargs)

    args, unknowns = parse_args_include_unknowns(parser, argv)
    quick_command = get_quick_command(unknowns)

    if args.version:
        print(json.dumps(conf.ICON_VERSIONS, indent=2))
        parser.exit()

    command_arguments.set_raw_commands(args)

    if args.radio_station_target == 'testnet':
        args.radio_station_target = conf.URL_CITIZEN_TESTNET
        args.configure_file_path = conf.CONF_PATH_LOOPCHAIN_TESTNET
    elif args.radio_station_target == 'mainnet':
        args.radio_station_target = conf.URL_CITIZEN_MAINNET
        args.configure_file_path = conf.CONF_PATH_LOOPCHAIN_MAINNET

    if args.configure_file_path:
        conf.Configure().load_configure_json(args.configure_file_path)

    if args.develop:
        loggers.set_preset_type(loggers.PresetType.develop)
    else:
        loggers.set_preset_type(loggers.PresetType.production)
    logger_preset = loggers.get_preset()
    logger_preset.service_type = args.service_type
    loggers.update_preset(False)
    loggers.update_other_loggers()

    grpc_patcher.monkey_patch()
    async_.thread_monkey_patch()
    async_.concurrent_future_monkey_patch()

    if args.service_type in ("peer", "citizen"):
        start_as_peer(args)
    elif args.service_type == "rest":
        start_as_rest_server(args)
    elif args.service_type == "score":
        start_as_score(args)
    elif args.service_type == "channel":
        start_as_channel(args)
    elif args.service_type == "tool":
        start_as_tool(args, quick_command)
    elif args.service_type == "admin":
        start_as_admin(args, quick_command)
    else:
        print(f"not supported service type {args.service_type}\ncheck loopchain help.\n")
        parser.print_help()


def check_port_available(port):
    # Check Port is Using
    if utils.check_port_using(int(port)):
        utils.exit_and_msg(f"not available port({port})")


def start_as_channel(args):
    # apply default configure values
    channel = args.channel or conf.LOOPCHAIN_DEFAULT_CHANNEL
    amqp_target = args.amqp_target or conf.AMQP_TARGET
    amqp_key = args.amqp_key or conf.AMQP_KEY

    ChannelService(channel, amqp_target, amqp_key, rollback=args.rollback).serve()


def start_as_rest_server(args):
    from iconcommons.icon_config import IconConfig
    from iconcommons.logger import Logger
    from iconrpcserver.default_conf.icon_rpcserver_config import default_rpcserver_config
    from iconrpcserver import icon_rpcserver_app

    amqp_key = args.amqp_key or conf.AMQP_KEY
    api_port = int(args.port) + conf.PORT_DIFF_REST_SERVICE_CONTAINER
    conf_path = conf.CONF_PATH_ICONRPCSERVER_DEV

    if args.radio_station_target == conf.URL_CITIZEN_TESTNET:
        conf_path = conf.CONF_PATH_ICONRPCSERVER_TESTNET
    elif args.radio_station_target == conf.URL_CITIZEN_MAINNET:
        conf_path = conf.CONF_PATH_ICONRPCSERVER_MAINNET

    additional_conf = {
        "port": api_port,
        "amqpTarget": conf.AMQP_TARGET,
        "amqpKey": amqp_key,
        "channel": conf.LOOPCHAIN_DEFAULT_CHANNEL
    }

    rpcserver_conf: IconConfig = IconConfig(conf_path, default_rpcserver_config)
    rpcserver_conf.load()
    rpcserver_conf.update_conf(additional_conf)
    Logger.load_config(rpcserver_conf)

    icon_rpcserver_app.run_in_foreground(rpcserver_conf)


def start_as_score(args):
    from iconservice.icon_service import IconService
    from iconservice.icon_config import default_icon_config
    from iconcommons.icon_config import IconConfig
    from iconcommons.logger import Logger

    port = args.port or conf.PORT_PEER
    channel = args.channel or conf.LOOPCHAIN_DEFAULT_CHANNEL
    amqp_target = args.amqp_target or conf.AMQP_TARGET
    amqp_key = args.amqp_key or conf.AMQP_KEY
    conf_path = conf.CONF_PATH_ICONSERVICE_DEV

    if args.develop:
        db_suffix = f"{port}_{channel}"
    else:
        db_suffix = channel

    if args.radio_station_target == conf.URL_CITIZEN_TESTNET:
        conf_path = conf.CONF_PATH_ICONSERVICE_TESTNET
    elif args.radio_station_target == conf.URL_CITIZEN_MAINNET:
        conf_path = conf.CONF_PATH_ICONSERVICE_MAINNET

    network_type = conf_path.split('/')[-2]
    with open(conf_path) as file:
        load_conf = json.load(file)

    additional_conf = {
        "log": {
            "filePath": f"./log/{network_type}/{db_suffix}/iconservice.log"
        },
        "scoreRootPath": conf.DEFAULT_STORAGE_PATH + f"/.score_{db_suffix}",
        "stateDbRootPath": conf.DEFAULT_STORAGE_PATH + f"/.statedb_{db_suffix}",
        "channel": channel,
        "amqpKey": amqp_key,
        "amqpTarget": amqp_target
    }

    icon_conf: IconConfig = IconConfig("", default_icon_config)
    icon_conf.load()
    icon_conf.update_conf(load_conf)
    icon_conf.update_conf(additional_conf)
    Logger.load_config(icon_conf)

    icon_service = IconService()
    icon_service.serve(config=icon_conf)


def start_as_admin(args, quick_command):
    print_prologue()
    try:
        from _tools.loopchain_private_tools import gtool
    except Exception as e:
        logging.error(f"admin service does not be provided. {e}")
    else:
        gtool.main(quick_command)

    print_epilogue()


def start_as_tool(args, quick_command):
    print_prologue()

    try:
        from _tools.loopchain_private_tools.demotool import DemoTool
    except Exception as e:
        logging.error(f"tool service does not be provided. {e}")
    else:
        DemoTool().main()

    print_epilogue()


def start_as_peer(args):
    print_prologue()

    # apply default configure values
    port = args.port or conf.PORT_PEER
    amqp_target = args.amqp_target or conf.AMQP_TARGET
    amqp_key = args.amqp_key or conf.AMQP_KEY

    if conf.CHANNEL_BUILTIN:
        if not amqp_key or amqp_key == conf.AMQP_KEY_DEFAULT:
            amqp_key = f"{utils.get_private_ip()}:{port}"
            command_arguments.add_raw_command(command_arguments.Type.AMQPKey, amqp_key)

    check_port_available(int(port))

    PeerService().serve(
        port=port,
        agent_pin=args.agent_pin,
        amqp_target=amqp_target,
        amqp_key=amqp_key
    )

    print_epilogue()


def print_prologue():
    print()
    print("                 ##                                                                                ")
    print("         #     ###                                                                                 ")
    print("      #######  ###                                                                                 ")
    print("     ########                                                                                      ")
    print("    ####   #          ###   #######    #######   ###   ###  ###      #######     ######    ####### ")
    print("   ####       ##      ###  #########  #########  ####  ###  ###     #########   ########   ########")
    print("   ###       ###      ### ###    ### ###    ###  ##### ###  ###     ###    ### ###    ###  ##    ##")
    print("   ##         ##      ### ###        ###     ### ##### ###  ###     ##     ### ##      ##  ##    ##")
    print("   ##         ##      ### ##         ###     ### ## ######  ###     ##      ## ##      ##  ##    ##")
    print("   ###        ##      ### ###     ## ###     ##  ##  #####  ###     ##     ### ##     ###  ########")
    print("   ###       ###      ### ####   ### ####   ###  ##   ####  ###     ###   #### ###   ####  ####### ")
    print("    #       ####      ###  ########   ########   ##    ###  #######  ########   ########   ##      ")
    print("       ########       ###   ######     ######    ##    ###  ######    ######     ######    ##      ")
    print("  ## #########                                                                                     ")
    print(" ####  #####                                                                                       ")
    print("  ###                                                                                              ")
    print()


def print_epilogue():
    time.sleep(0.1)
    print()
    print("                 $$                                                                                ")
    print("         $     $$$                                                                                 ")
    print("      $$$$$$$  $$$                                                                                 ")
    print("     $$$$$$$$                                                                                      ")
    print("    $$$$   $          $$$   $$$$$$$    $$$$$$$   $$$   $$$  $$$      $$$$$$$     $$$$$$    $$$$$$$ ")
    print("   $$$$       $$      $$$  $$$$$$$$$  $$$$$$$$$  $$$$  $$$  $$$     $$$$$$$$$   $$$$$$$$   $$$$$$$$")
    print("   $$$       $$$      $$$ $$$    $$$ $$$    $$$  $$$$$ $$$  $$$     $$$    $$$ $$$    $$$  $$    $$")
    print("   $$         $$      $$$ $$$        $$$     $$$ $$$$$ $$$  $$$     $$     $$$ $$      $$  $$    $$")
    print("   $$         $$      $$$ $$         $$$     $$$ $$ $$$$$$  $$$     $$      $$ $$      $$  $$    $$")
    print("   $$$        $$      $$$ $$$     $$ $$$     $$  $$  $$$$$  $$$     $$     $$$ $$     $$$  $$$$$$$$")
    print("   $$$       $$$      $$$ $$$$   $$$ $$$$   $$$  $$   $$$$  $$$     $$$   $$$$ $$$   $$$$  $$$$$$$ ")
    print("    $       $$$$      $$$  $$$$$$$$   $$$$$$$$   $$    $$$  $$$$$$$  $$$$$$$$   $$$$$$$$   $$      ")
    print("       $$$$$$$$       $$$   $$$$$$     $$$$$$    $$    $$$  $$$$$$    $$$$$$     $$$$$$    $$      ")
    print("  $$ $$$$$$$$$                                                                                     ")
    print(" $$$$  $$$$$                                                                                       ")
    print("  $$$                                                                                              ")
    print()
