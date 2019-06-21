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
""" A massage class for the loopchain """


class Request:
    status = 1
    is_alive = 2
    stop = -9

    peer_peer_list = 600
    peer_get_leader = 601  # get leader peer object
    peer_complain_leader = 602  # complain leader peer is no response
    peer_reconnect_to_rs = 603  # reconnect to rs when rs restart detected.
    peer_restart_channel = 604

    rs_get_configuration = 800
    rs_set_configuration = 801
    rs_send_channel_manage_info_to_rs = 802
    rs_restart_channel = 803
    rs_delete_peer = 804

    tx_connect_to_leader = 901  # connect to leader
    tx_connect_to_inner_peer = 902  # connect to mother peer service in same inner gRPC micro service network
    get_tx_result = 903  # json-rpc:icx_getTransactionResult
    get_balance = 905  # josn-rpc:icx_getBalance
    get_tx_by_address = 906  # json-rpc:icx_getTransactionByAddress
    get_total_supply = 907  # json-rpc:icx_getTotalSupply


class MetaParams:
    class ScoreInfo:
        score_id = "score_id"
        score_version = "score_version"


class Response:
    success = 0
    success_validate_block = 1
    success_announce_block = 2
    fail = -1
    fail_validate_block = -2
    fail_announce_block = -3
    fail_wrong_block_hash = -4
    fail_no_leader_peer = -5
    fail_validate_params = -6
    fail_wrong_subscribe_info = -8
    fail_connect_to_leader = -9
    fail_add_tx_to_leader = -10
    fail_create_tx = -11
    fail_invalid_peer_target = -12
    fail_not_enough_data = -13
    fail_tx_pre_validate = -14
    fail_subscribe_limit = -15
    fail_invalid_key_error = -16
    fail_wrong_block_height = -17
    fail_no_permission = -18
    fail_out_of_tps_limit = -19
    fail_connection_closed = -20
    fail_tx_invalid_unknown = -100
    fail_tx_invalid_hash_format = -101
    fail_tx_invalid_hash_generation = -102
    fail_tx_invalid_hash_not_match = -103
    fail_tx_invalid_address_not_match = -104
    fail_tx_invalid_address_format = -105
    fail_tx_invalid_signature = -106
    fail_tx_invalid_params = -107
    fail_tx_invalid_duplicated_hash = -108
    fail_tx_invalid_out_of_time_bound = -109
    fail_tx_invalid_wrong_nid = -110
    fail_tx_not_invoked = -111
    fail_score_invoke = -200
    fail_score_invoke_result = -201

    fail_no_peer_info_in_rs = -800
    timeout_exceed = -900
    not_treat_message_code = -999
    fail_illegal_params = -1000


responseCodeMap = {
    Response.success:
        (Response.success, "success"),

    Response.success_validate_block:
        (Response.success_validate_block, "success validate block"),

    Response.success_announce_block:
        (Response.success_announce_block, "success announce block"),

    Response.fail:
        (Response.fail, "fail"),

    Response.fail_validate_block:
        (Response.fail_validate_block, "fail validate block"),

    Response.fail_announce_block:
        (Response.fail_announce_block, "fail announce block"),

    Response.fail_wrong_block_hash:
        (Response.fail_wrong_block_hash, "fail wrong block hash"),

    Response.fail_no_leader_peer:
        (Response.fail_no_leader_peer, "fail no leader peer"),

    Response.fail_validate_params:
        (Response.fail_validate_params, "fail validate params"),

    Response.fail_wrong_subscribe_info:
        (Response.fail_wrong_subscribe_info, "fail wrong subscribe info"),

    Response.fail_connect_to_leader:
        (Response.fail_connect_to_leader, "fail connect to leader"),

    Response.fail_add_tx_to_leader:
        (Response.fail_add_tx_to_leader, "fail add tx to leader"),

    Response.fail_invalid_peer_target:
        (Response.fail_invalid_peer_target, "fail invalid peer target for channel"),

    Response.fail_not_enough_data:
        (Response.fail_not_enough_data, "fail not enough data"),

    Response.fail_tx_pre_validate:
        (Response.fail_tx_pre_validate, "fail tx pre-validate"),

    Response.fail_subscribe_limit:
        (Response.fail_subscribe_limit, "fail subscribe limit"),

    Response.fail_no_peer_info_in_rs:
        (Response.fail_no_peer_info_in_rs, "fail no peer info in radio station"),

    Response.fail_create_tx:
        (Response.fail_create_tx, "fail create tx to peer"),

    Response.fail_wrong_block_height:
        (Response.fail_wrong_block_height, "fail wrong block height"),

    Response.fail_no_permission:
        (Response.fail_no_permission, "fail no permission"),

    Response.fail_out_of_tps_limit:
        (Response.fail_out_of_tps_limit, "Server is processing too many requests"),

    Response.fail_tx_invalid_unknown:
        (Response.fail_tx_invalid_unknown, "fail tx invalid unknown"),

    Response.fail_tx_invalid_hash_format:
        (Response.fail_tx_invalid_hash_format, "fail tx invalid hash format"),

    Response.fail_tx_invalid_hash_generation:
        (Response.fail_tx_invalid_hash_generation, "fail tx invalid hash generation"),

    Response.fail_tx_invalid_address_not_match:
        (Response.fail_tx_invalid_address_not_match, "fail tx invalid address not match"),

    Response.fail_tx_invalid_address_format:
        (Response.fail_tx_invalid_address_format, "fail tx invalid address"),

    Response.fail_tx_invalid_hash_not_match:
        (Response.fail_tx_invalid_hash_not_match, "fail tx invalid hash not match"),

    Response.fail_tx_invalid_signature:
        (Response.fail_tx_invalid_signature, "fail tx invalid signature"),

    Response.fail_tx_invalid_params:
        (Response.fail_tx_invalid_params, "fail tx invalid params"),

    Response.fail_tx_invalid_duplicated_hash:
        (Response.fail_tx_invalid_duplicated_hash, "fail tx invalid duplicated hash"),

    Response.fail_tx_invalid_out_of_time_bound:
        (Response.fail_tx_invalid_out_of_time_bound, "fail tx invalid out of time bound"),

    Response.fail_tx_invalid_wrong_nid:
        (Response.fail_tx_invalid_wrong_nid, "fail tx invalid no nid"),

    Response.fail_tx_not_invoked:
        (Response.fail_tx_not_invoked, "Pending transaction"),

    Response.timeout_exceed:
        (Response.timeout_exceed, "timeout exceed"),

    Response.fail_illegal_params:
        (Response.fail_illegal_params, "fail_illegal_params")
}


def get_response_code(code):
    return responseCodeMap[code][0]


def get_response_msg(code):
    return responseCodeMap[code][1]


def get_response(code):
    return responseCodeMap[code][0], responseCodeMap[code][1]
