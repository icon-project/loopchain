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
import os
import time
from urllib.parse import urlparse, ParseResult

import loopchain.utils as util
from loopchain import configure as conf
from loopchain.channel.channel_service import ChannelService
from loopchain.peer import PeerService
from loopchain.radiostation import RadioStationService
from loopchain.rest_server.rest_server_rs import ServerComponents as RSServerComponents
from loopchain.tools.grpc_helper import grpc_patcher
from loopchain.utils import loggers, command_arguments, async_


def main(argv):
    parser = argparse.ArgumentParser()
    for cmd_arg_type in command_arguments.Type:
        cmd_arg_attr = command_arguments.attributes[cmd_arg_type]
        parser.add_argument(*cmd_arg_attr.names, **cmd_arg_attr.kwargs)

    args = parser.parse_args(argv)
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

    if args.service_type == "peer":
        start_as_peer(args, conf.NodeType.CommunityNode)
    elif args.service_type == "citizen":
        start_as_peer(args, conf.NodeType.CitizenNode)
    elif args.service_type == "rs" or args.service_type == "radiostation":
        start_as_rs(args)
    elif args.service_type == "rest":
        start_as_rest_server(args)
    elif args.service_type == "rest-rs":
        start_as_rest_server_rs(args)
    elif args.service_type == "score":
        start_as_score(args)
    elif args.service_type == "channel":
        start_as_channel(args)
    elif args.service_type == "tool":
        start_as_tool(args)
    elif args.service_type == "admin":
        start_as_admin(args)
    else:
        print(f"not supported service type {args.service_type}\ncheck loopchain help.\n")
        os.system("python3 ./loopchain.py -h")


def check_port_available(port):
    # Check Port is Using
    if util.check_port_using(int(port)):
        util.exit_and_msg(f"not available port({port})")


def start_as_channel(args):
    # apply default configure values
    channel = args.channel or conf.LOOPCHAIN_DEFAULT_CHANNEL
    amqp_target = args.amqp_target or conf.AMQP_TARGET
    amqp_key = args.amqp_key or conf.AMQP_KEY

    ChannelService(channel, amqp_target, amqp_key).serve()


def start_as_rest_server(args):
    from iconcommons.icon_config import IconConfig
    from iconrpcserver.default_conf.icon_rpcserver_config import default_rpcserver_config
    from iconrpcserver import icon_rpcserver_cli

    amqp_key = args.amqp_key or conf.AMQP_KEY
    api_port = int(args.port) + conf.PORT_DIFF_REST_SERVICE_CONTAINER
    conf_path = conf.CONF_PATH_ICONRPCSERVER_DEV

    if args.radio_station_target == conf.URL_CITIZEN_TESTNET:
        conf_path = conf.CONF_PATH_ICONRPCSERVER_TESTNET
    elif args.radio_station_target == conf.URL_CITIZEN_MAINNET:
        conf_path = conf.CONF_PATH_ICONRPCSERVER_MAINNET

    additional_conf = {
        "port": api_port,
        "config": conf_path,
        "amqpTarget": conf.AMQP_TARGET,
        "amqpKey": amqp_key,
        "channel": conf.LOOPCHAIN_DEFAULT_CHANNEL,
        "tbearsMode": False
    }

    rpcserver_conf: IconConfig = IconConfig("", default_rpcserver_config)
    rpcserver_conf.load()
    rpcserver_conf.update_conf(additional_conf)

    icon_rpcserver_cli.start(rpcserver_conf)


def start_as_rest_server_rs(args):
    rs_port = args.port
    api_port = int(rs_port) + conf.PORT_DIFF_REST_SERVICE_CONTAINER

    RSServerComponents().set_resource()
    RSServerComponents().set_stub_port(port=rs_port)

    logging.info(f"Sanic rest server for RS is running!: {api_port}")
    RSServerComponents().serve(api_port)


def start_as_score(args):
    from iconservice.icon_service import IconService
    from iconservice.icon_config import default_icon_config
    from iconcommons.icon_config import IconConfig
    from iconcommons.logger import Logger

    channel = args.channel or conf.LOOPCHAIN_DEFAULT_CHANNEL
    amqp_target = args.amqp_target or conf.AMQP_TARGET
    amqp_key = args.amqp_key or conf.AMQP_KEY
    conf_path = conf.CONF_PATH_ICONSERVICE_DEV

    if args.radio_station_target == conf.URL_CITIZEN_TESTNET:
        conf_path = conf.CONF_PATH_ICONSERVICE_TESTNET
    elif args.radio_station_target == conf.URL_CITIZEN_MAINNET:
        conf_path = conf.CONF_PATH_ICONSERVICE_MAINNET

    network_type = conf_path.split('/')[-2]
    with open(conf_path) as file:
        load_conf = json.load(file)

    additional_conf = {
        "log": {
            "filePath": f"./log/{network_type}/{channel}/iconservice_{amqp_key}.log"
        },
        "scoreRootPath": conf.DEFAULT_STORAGE_PATH + f"/.score_{amqp_key}_{channel}",
        "stateDbRootPath": conf.DEFAULT_STORAGE_PATH + f"/.statedb_{amqp_key}_{channel}",
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


def start_as_rs(args):
    print_prologue()

    # apply default configure values
    port = args.port or conf.PORT_RADIOSTATION
    cert = args.cert or None
    pw = None
    seed = args.seed or None
    check_port_available(int(port))

    if seed:
        try:
            seed = int(seed)
        except ValueError as e:
            util.exit_and_msg(f"seed or s opt must be int \n"
                              f"input value : {seed}")

    RadioStationService(conf.IP_RADIOSTATION, cert, pw, seed).serve(port)
    print_eplilogue()


def start_as_admin(args):
    print_prologue()
    try:
        from _tools.loopchain_private_tools import gtool
    except Exception as e:
        logging.error(f"admin service does not be provided. {e}")
    else:
        gtool.main()

    print_eplilogue()


def start_as_tool(args):
    print_prologue()

    try:
        from _tools.loopchain_private_tools import demotool
    except Exception as e:
        logging.error(f"tool service does not be provided. {e}")
    else:
        demotool.main_menu(True)

    print_eplilogue()


def start_as_peer(args, node_type=None):
    print_prologue()

    # apply default configure values
    port = args.port or conf.PORT_PEER
    radio_station_target = f"{conf.IP_RADIOSTATION}:{conf.PORT_RADIOSTATION}"
    amqp_target = args.amqp_target or conf.AMQP_TARGET
    amqp_key = args.amqp_key or conf.AMQP_KEY

    if conf.CHANNEL_BUILTIN:
        if not amqp_key or amqp_key == conf.AMQP_KEY_DEFAULT:
            amqp_key = f"{util.get_private_ip()}:{port}"
            command_arguments.add_raw_command(command_arguments.Type.AMQPKey, amqp_key)

    check_port_available(int(port))

    if node_type is None:
        node_type = conf.NodeType.CommunityNode
    elif node_type == conf.NodeType.CitizenNode and not args.radio_station_target:
        util.exit_and_msg(f"citizen node needs subscribing peer target input")

    if args.radio_station_target:
        try:
            parse_result: ParseResult = urlparse(args.radio_station_target)

            if conf.SUBSCRIBE_USE_HTTPS:
                if not parse_result.scheme:
                    parse_result = urlparse(f"https://{args.radio_station_target}")
            else:
                if not parse_result.scheme:
                    parse_result = urlparse(f"http://{args.radio_station_target}")
                    if not parse_result.port:
                        parse_result = urlparse(f"http://{args.radio_station_target}:{conf.PORT_RADIOSTATION}")

            radio_station_target = parse_result.netloc

        except Exception as e:
            util.exit_and_msg(f"'-r' or '--radio_station_target' option requires "
                              f"[IP Address of Radio Station]:[PORT number of Radio Station], "
                              f"or just [IP Address of Radio Station] format. error({e})")

    # run peer service with parameters
    logging.info(f"loopchain peer run with: port({port}) "
                 f"radio station target({radio_station_target})")

    PeerService(
        radio_station_target=radio_station_target,
        node_type=node_type
    ).serve(
        port=port,
        agent_pin=args.agent_pin,
        amqp_target=amqp_target,
        amqp_key=amqp_key
    )

    print_eplilogue()


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


def print_eplilogue():
    time.sleep(0.1)
    print()
    print('             ,            ')
    print('            /|      __    ')
    print('           / |   ,-~ /    ')
    print('          Y :|  //  /     ')
    print('          | jj /( .^      ')
    print('          >-"~"-v"        ')
    print('         /       Y        ')
    print('        jo  o    |        ')
    print('       ( ~T~     j        ')
    print("        >._-' _./         ")
    print('       /   "~"  |         ')
    print('      Y     _,  |         ')
    print('     /| ;-"~ _  l         ')
    print('    / l/ ,-"~    \        ')
    print('    \//\/      .- \       ')
    print('     Y        /    Y      ')
    print('     l       I     !      ')
    print('     ]\      _\    /"\    ')
    print('    (" ~----( ~   Y.  )   ')
    print('~~~~~~~~~~~~~~~~~~~~~~~~~~')
    print('To the moon.')
    print()
