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

import copy
import logging
import traceback
from enum import Enum

key_converting = object()


class ParamType(Enum):
    send_tx = 0
    call = 1
    get_balance = 2
    get_score_api = 3
    get_total_supply = 4
    invoke = 5
    write_precommit_state = 6
    remove_precommit_state = 7
    get_block_by_hash_request = 8
    get_block_by_height_request = 9
    get_block_response = 10
    get_tx_request = 11
    get_tx_by_hash_response = 12
    get_tx_result_response = 13
    send_tx_response = 14
    roll_back = 15
    change_block_hash = 16
    pre_invoke = 17


class ValueType(Enum):
    none = 0
    text = 1
    integer = 2
    hex_number = 3
    hex_0x_number = 4
    hex_0x_number_16 = 5
    hex_0x_hash_number = 6


def convert_params(params, param_type):
    if param_type is None:
        return params

    obj = _convert(params, templates[param_type])
    return obj


def _convert(obj, template):
    if not obj or not template:
        return copy.deepcopy(obj)

    if isinstance(template, dict) and key_converting in template:
        obj = _convert_key(obj, template[key_converting])

    if isinstance(obj, dict) and isinstance(template, dict):
        new_obj = dict()
        for key, value in obj.items():
            new_value = _convert(value, template.get(key, None))
            new_obj[key] = new_value

    elif isinstance(obj, list) and isinstance(template, list):
        new_obj = list()
        for item in obj:
            new_item = _convert(item, template[0])
            new_obj.append(new_item)

    elif isinstance(template, ValueType):
        new_obj = _convert_value(obj, template)

    else:
        new_obj = obj

    return new_obj


def _convert_key(obj, key_convert_dict):
    new_obj = dict()
    for key in obj:
        if key in key_convert_dict:
            old_key = key
            new_key = key_convert_dict[old_key]
            new_obj[new_key] = obj[old_key]
        else:
            new_obj[key] = obj[key]

    return new_obj


def _convert_value(value, value_type):
    try:
        if value_type == ValueType.none:
            return value
        elif value_type == ValueType.text:
            return _convert_value_text(value)
        elif value_type == ValueType.integer:
            return _convert_value_integer(value)
        elif value_type == ValueType.hex_number:  # hash...(block_hash, tx_hash)
            return _convert_value_hex_number(value)
        elif value_type == ValueType.hex_0x_number:
            return _convert_value_hex_0x_number(value)
        elif value_type == ValueType.hex_0x_number_16:
            return _convert_value_hex_0x_number_16(value)
        elif value_type == ValueType.hex_0x_hash_number:
            return _convert_value_hex_0x_hash_number(value)

    except BaseException as e:
        traceback.print_exc()
        logging.error(f"Error : {e}, value : {value_type}:{value}")

    return value


def _convert_value_text(value):
    if isinstance(value, str):
        return value
    return str(value)


def _convert_value_integer(value):
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        if value.startswith('0x') or value.startswith('-0x'):
            return int(value, 16)
        try:
            return int(value)
        except:
            pass
        return int(value, 16)


def _convert_value_hex_number(value):
    if isinstance(value, int):
        return hex(value).replace('0x', '')
    if isinstance(value, str):
        hex(int(value, 16))  # if no raise
        return value.replace('0x', '')


def _convert_value_hex_0x_number(value):
    if isinstance(value, int):
        return hex(value)
    if isinstance(value, str):
        if value.startswith('0x') or value.startswith('-0x'):
            return value

        try:
            return hex(int(value))
        except:
            pass
        return hex(int(value, 16))


def _convert_value_hex_0x_number_16(value):
    if isinstance(value, int):
        return hex(value)
    if isinstance(value, str):
        if value.startswith('0x') or value.startswith('-0x'):
            return value

        try:
            return hex(int(value, 16))
        except:
            pass


def _convert_value_hex_0x_hash_number(value):
    if isinstance(value, int):
        return hex(value)
    if isinstance(value, str):
        if value.startswith('0x') or value.startswith('-0x'):
            return value

        num = int(value, 16)
        hex(int(value, 16))
        if num > 0:
            return '0x' + value
        else:
            return '-0x' + value


templates = dict()
templates[ParamType.send_tx] = {
    "method": ValueType.text,
    "params": {
        "version": ValueType.text,
        "from": ValueType.none,
        "to": ValueType.none,
        "value": ValueType.hex_0x_number_16,
        "fee": ValueType.hex_0x_number_16,
        "stepLimit": ValueType.hex_0x_number,
        "timestamp": ValueType.hex_0x_number,
        "nonce": ValueType.hex_0x_number,
        "signature": ValueType.text,
        "dataType": ValueType.text,
        "txHash": ValueType.hex_number,
        key_converting: {
            "tx_hash": "txHash",
            "time_stamp": "timestamp"
        }
    },
    "genesisData": ValueType.none
}

templates[ParamType.call] = {
    "method": ValueType.text,
    "params": {
        "to": ValueType.none,
        "dataType": ValueType.text,
        "data": {
            "method": ValueType.text,
            "params": {
                "address": ValueType.none
            }
        }
    }
}

templates[ParamType.get_balance] = {
    "method": ValueType.text,
    "params": {
        "address": ValueType.none
    }
}

templates[ParamType.get_score_api] = templates[ParamType.get_balance]

templates[ParamType.get_total_supply] = {
    "method": ValueType.text
}

templates[ParamType.invoke] = {
    "block": {
        "blockHeight": ValueType.hex_0x_number,
        "blockHash": ValueType.hex_number,
        "timestamp": ValueType.hex_0x_number,
        "prevBlockHash": ValueType.hex_number,
        key_converting: {
            "block_height": "blockHeight",
            "block_hash": "blockHash",
            "time_stamp": "timestamp"
        }
    },
    "transactions": [
        templates[ParamType.send_tx]
    ]
}

templates[ParamType.write_precommit_state] = {
    "blockHeight": ValueType.hex_0x_number,
    "blockHash": ValueType.hex_number
}

templates[ParamType.remove_precommit_state] = templates[ParamType.write_precommit_state]

templates[ParamType.roll_back] = templates[ParamType.write_precommit_state]

templates[ParamType.pre_invoke] = templates[ParamType.write_precommit_state]

templates[ParamType.get_block_by_hash_request] = {
    "hash": ValueType.hex_number
}

templates[ParamType.get_block_by_height_request] = {
    "height": ValueType.integer
}

templates[ParamType.get_block_response] = {
    "confirmed_transaction_list": [
        {
            "txHash": ValueType.hex_0x_hash_number
        }
    ]
}

templates[ParamType.get_tx_request] = {
    "txHash": ValueType.hex_number
}

templates[ParamType.get_tx_result_response] = {
    "txHash": ValueType.hex_0x_hash_number,
    "blockHash": ValueType.hex_0x_hash_number,
}

templates[ParamType.get_tx_by_hash_response] = {
    "txHash": ValueType.hex_0x_hash_number,
    "blockHeight": ValueType.hex_0x_number,
    "blockHash": ValueType.hex_0x_hash_number
}

templates[ParamType.send_tx_response] = ValueType.hex_0x_hash_number

templates[ParamType.change_block_hash] = {
    "blockHeight": ValueType.hex_0x_number,
    "oldBlockHash": ValueType.hex_number,
    "newBlockHash": ValueType.hex_number
}
