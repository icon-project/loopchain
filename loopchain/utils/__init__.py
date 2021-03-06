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
""" A module for utility"""

import datetime
import importlib.machinery
import json
import logging
import os
import re
import signal
import socket
import sys
import time
import traceback
from binascii import unhexlify
from contextlib import closing
from decimal import Decimal
from pathlib import Path
from subprocess import PIPE, Popen, TimeoutExpired
from typing import Tuple, Union

import verboselogs

from loopchain import configure as conf
from loopchain.store.key_value_store import KeyValueStoreError, KeyValueStore
from loopchain.tools.grpc_helper import GRPCHelper

logger = verboselogs.VerboseLogger("dev")


def long_to_bytes(val, endianness='big'):
    """Use :ref:`string formatting` and :func:`~binascii.unhexlify` to
    convert ``val``, a :func:`long`, to a byte :func:`str`.

    :param long val: The value to pack

    :param str endianness: The endianness of the result. ``'big'`` for
      big-endian, ``'little'`` for little-endian.

    If you want byte- and word-ordering to differ, you're on your own.

    Using :ref:`string formatting` lets us use Python's C innards.
    """

    # one (1) hex digit per four (4) bits
    width = val.bit_length()

    # unhexlify wants an even multiple of eight (8) bits, but we don't
    # want more digits than we need (hence the ternary-ish 'or')
    width += 8 - ((width % 8) or 8)

    # format width specifier: four (4) bits per hex digit
    fmt = '%%0%dx' % (width // 4)

    # prepend zero (0) to the width, to zero-pad the output
    s = unhexlify(fmt % val)

    if endianness == 'little':
        # see http://stackoverflow.com/a/931095/309233
        s = s[::-1]

    return s


def exit_and_msg(msg):
    traceback.print_stack()

    exit_msg = "Service Stop by: " + msg
    logging.exception(exit_msg)

    # To make sure of terminating process exactly
    os.killpg(0, signal.SIGKILL)
    time.sleep(5)

    os.kill(os.getpid(), signal.SIGKILL)
    time.sleep(5)

    os._exit(-1)
    time.sleep(5)

    sys.exit(-1)


def _load_user_score_module(path, call_class_name):
    """for support load multifile like package. (lagacy only support 1 .py file)
    set package path to sys.path before load ScoreObject

    :param path: score file path (not dir_path)
    :param call_class_name: call module name
    :return: user_score_module
    """

    dir_path = os.path.dirname(path)

    if dir_path in sys.path:
        logging.debug(f"sys.path has the score path: {dir_path}")
    else:
        sys.path.append(dir_path)

    user_module = importlib.machinery.SourceFileLoader(call_class_name, path).load_module()
    return user_module.UserScore


def load_user_score(path):
    """file path 로 부터 사용자 score object를 구한다.

    :param path: 사용자 score의 python 파일 (*.py)
    :return: 사용자 score 에 정의된 UserScore Object
    """
    return _load_user_score_module(path, "UserScore")


def get_stub_to_server(target, stub_class, ssl_auth_type: conf.SSLAuthType = conf.SSLAuthType.none):
    """gRPC connection to server

    :return: stub to server
    """

    stub = None
    channel = None

    try:
        logging.debug(f"(util) get stub to server target: {target}")
        channel = GRPCHelper().create_client_channel(target, ssl_auth_type, conf.GRPC_SSL_KEY_LOAD_TYPE)
        stub = stub_class(channel)
    except Exception as e:
        logging.warning(f"Connect to Server Error(get_stub_to_server): {e}")

    return stub, channel


def normalize_request_url(url_input, version=None, channel=None):
    use_https = False

    if 'http://' in url_input:
        url_input = url_input.split("http://")[1]

    if 'https://' in url_input:
        use_https = True

    if not url_input:  # ex) '' => http://localhost:9000/api/v3
        url = generate_url_from_params(version=version, channel=channel)
    elif 'https://' in url_input and url_input.count(':') == 1:  # ex) https://testwallet.icon.foundation
        url = generate_url_from_params(dns=url_input.split("https://")[1],
                                       version=version,
                                       use_https=True,
                                       channel=channel)
    elif 'https://' in url_input and url_input.count(':') == 2:  # ex) https://127.0.0.1:9000
        ip_port = url_input.split("https://")[1]
        url = generate_url_from_params(ip=ip_port.split(':')[0],
                                       port=ip_port.split(':')[1],
                                       version=version,
                                       use_https=True,
                                       channel=channel)
    elif url_input.isdigit():  # ex) 9000
        url = generate_url_from_params(port=url_input, version=version, channel=channel)
    elif ':' in url_input and url_input.split(':')[1].isdigit():  # ex) 127.0.0.1:9000, {peer_name}:9000
        url = generate_url_from_params(ip=url_input.split(":")[0],
                                       port=url_input.split(":")[1],
                                       version=version,
                                       channel=channel)
    elif url_input.count('.') == 3 and url_input.replace(".", "").isdigit():  # ex) 127.0.0.1
        url = generate_url_from_params(ip=url_input, version=version, channel=channel)
    else:  # ex) testwallet.icon.foundation => https://testwallet.icon.foundation/api/v3
        url = generate_url_from_params(dns=url_input, version=version, use_https=use_https, channel=channel)

    return url


def generate_url_from_params(ip=None, dns=None, port=None, version=None, use_https=False, channel=None):
    ip = ip or conf.IP_LOCAL
    port = port or conf.PORT_PEER_FOR_REST
    version = version or conf.ApiVersion.v3
    channel = channel or conf.LOOPCHAIN_DEFAULT_CHANNEL
    scheme = 'https' if use_https else 'http'

    if dns:
        ip = dns
        port = '443'

    if version in (conf.ApiVersion.v3, conf.ApiVersion.node):
        url = f"{scheme}://{ip}:{port}/api/{version.name}/{channel}"
    else:
        url = f"{scheme}://{ip}:{port}/api/{version.name}"
    return url


def get_private_ip3():
    command = "ifconfig | grep -i \"inet\" | grep -iv \"inet6\" | grep -iv \"127.\" | " + \
              "awk {'print $2'}"
    process = Popen(
        args=command,
        stdout=PIPE,
        shell=True
    )
    return str(process.communicate()[0].decode(conf.HASH_KEY_ENCODING)).strip().split("\n")[0]


def get_private_ip2():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        result = s.getsockname()[0]
        s.close()
    except Exception as e:
        result = "127.0.0.1"
    return result


def check_is_private_ip(ip):
    private_ip_prefix = ["10", "172", "192"]

    if ip.split(".")[0] not in private_ip_prefix:
        return False

    return True


def check_is_json_string(json_string):
    if isinstance(json_string, str):
        try:
            json_object = json.loads(json_string)
            return True
        except json.JSONDecodeError as e:
            logging.warning("Fail Json decode: " + str(e))
            return False
    return False


def get_private_ip():
    docker_evn = Path("/.dockerenv")
    # IF CONFIGURE IS SETTING
    if conf.LOOPCHAIN_HOST is not None:
        return conf.LOOPCHAIN_HOST

    if docker_evn.is_file():
        logging.debug("It's working on docker. Trying to find private IP if it is in EC2.")
        command = "curl -s http://169.254.169.254/latest/meta-data/local-ipv4; echo"
        process = Popen(
            args=command,
            stdout=PIPE,
            shell=True
        )
        try:
            output = str(process.communicate(timeout=15)[0].decode(conf.HASH_KEY_ENCODING)).strip()
        except TimeoutExpired:
            logging.debug("Timed out! Docker container is working in local.")
            process.kill()
            return get_private_ip2()
        if check_is_private_ip(output):
            return output
        else:
            return get_private_ip2()
    else:
        ip = str(get_private_ip2())
        logging.debug("ip(with way2): " + ip)
        if check_is_private_ip(ip):
            return ip
        return get_private_ip3()


def convert_local_ip_to_private_ip(data: Union[list, dict]):
    converted = json.dumps(data).replace('[local_ip]', get_private_ip())
    return json.loads(converted)


def load_json_data(channel_manage_data_path: str):
    try:
        logging.debug(f"try to load channel management"
                      f" data from json file ({channel_manage_data_path})")
        with open(channel_manage_data_path) as file:
            json_data = json.load(file)

        json_data = convert_local_ip_to_private_ip(json_data)
        logging.info(f"loading channel info : {json_data}")
        return json_data
    except FileNotFoundError as e:
        exit_and_msg(f"cannot open json file in ({channel_manage_data_path}): {e}")
        raise


def dict_to_binary(the_dict):
    return str.encode(json.dumps(the_dict))


# Get Django Project get_valid_filename
# FROM https://github.com/django/django/blob/master/django/utils/encoding.py#L8
_PROTECTED_TYPES = (
    type(None), int, float, Decimal, datetime.datetime, datetime.date, datetime.time,
)


def get_time_stamp():
    return int(time.time() * 1_000_000)  # microseconds


def diff_in_seconds(timestamp):
    return int((get_time_stamp() - timestamp) / 1_000_000)


def get_timestamp_seconds(timestamp):
    return int(timestamp / 1_000_000)


def get_valid_filename(s):
    """Return the given string converted to a string that can be used for a clean
    filename. Remove leading and trailing spaces; convert other spaces to
    underscores; and remove anything that is not an alphanumeric, dash,
    underscore, or dot.
    >>> get_valid_filename("john's portrait in 2004.jpg")
    'john_sportraitin2004.jpg'
    >>> get_valid_filename("loopchain/default")
    'loopchain_default'
    """
    s = force_text(s).strip().replace(' ', '')
    return re.sub(r'(?u)[^-\w.]', '_', s)


def is_protected_type(obj):
    """Determine if the object instance is of a protected type.
    Objects of protected types are preserved as-is when passed to
    force_text(strings_only=True).
    """
    return isinstance(obj, _PROTECTED_TYPES)


def force_text(s, encoding='utf-8', strings_only=False, errors='strict'):
    """Similar to smart_text, except that lazy instances are resolved to
    strings, rather than kept as lazy objects.
    If strings_only is True, don't convert (some) non-string-like objects.
    """
    # Handle the common case first for performance reasons.
    if issubclass(type(s), str):
        return s
    if strings_only and is_protected_type(s):
        return s
    try:
        if isinstance(s, bytes):
            s = str(s, encoding, errors)
        else:
            s = str(s)
    except UnicodeDecodeError as e:
        raise UnicodeEncodeError(s, *e.args)
    return s


def check_port_using(port):
    """Check Port is Using

    :param port: check port
    :return: Using is True
    """
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        if sock.connect_ex((conf.IP_LOCAL, port)) == 0:
            return True
        else:
            return False


def datetime_diff_in_mins(start):
    diff = datetime.datetime.now() - start
    return divmod(diff.days * 86400 + diff.seconds, 60)[0]


def pretty_json(json_text, indent=4):
    return json.dumps(json.loads(json_text), indent=indent, separators=(',', ': '))


def parse_target_list(targets: str) -> list:
    targets_split_by_comma = targets.split(",")
    target_list = []

    for target in targets_split_by_comma:
        target_split = target.strip().split(":")
        target_list.append((target_split[0], int(target_split[1])))

    return target_list


def init_default_key_value_store(store_id: str) -> KeyValueStore:
    """init default key value store

    :param store_id: new identity of key-value store
    :return: KeyValueStore, store_path
    """
    if not os.path.exists(conf.DEFAULT_STORAGE_PATH):
        os.makedirs(conf.DEFAULT_STORAGE_PATH, exist_ok=True)

    store_path = os.path.join(conf.DEFAULT_STORAGE_PATH, f'db_{store_id}')
    logger.info(f"store_id={store_id}")

    retry_count = 0
    store = None
    uri = f"file://{store_path}"
    while store is None and retry_count < conf.MAX_RETRY_CREATE_DB:
        try:
            store = KeyValueStore.new(uri, create_if_missing=True)
        except KeyValueStoreError as e:
            logging.exception(f"KeyValueStore create failed: {e!r}")
            logger.debug(f"retry_count: {retry_count}, uri: {uri}")
        retry_count += 1

    if store is None:
        logging.error("Fail! Create key value store")
        raise KeyValueStoreError(f"Fail to create key value store. path={store_path}")

    return store


# ------------------- data utils ----------------------------

def is_hex(s):
    return re.fullmatch(r"^(0x)?[0-9a-f]{64}$", s or "") is not None


# ------------------- data utils ----------------------------


def get_now_time_stamp(init_time_seconds=None):
    time_seconds = time.time() if init_time_seconds is None else init_time_seconds
    return int(time_seconds * 1_000_000)


def is_in_time_boundary(timestamp, range_second, pivot_timestamp=None):
    if pivot_timestamp is None:
        pivot_timestamp = get_now_time_stamp()
    timestamp_range = get_now_time_stamp(range_second)
    left_timestamp_bound = pivot_timestamp - timestamp_range
    right_timestamp_bound = pivot_timestamp + timestamp_range
    return left_timestamp_bound <= timestamp <= right_timestamp_bound


def create_invoke_result_specific_case(confirmed_transaction_list, invoke_result):
    invoke_results = {}
    for tx in confirmed_transaction_list:
        invoke_results[tx.tx_hash] = invoke_result
    return invoke_results
