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
"""A module about Transaction object"""

import base64
import collections
import copy
import hashlib
import json
import logging
import struct
import time
from enum import Enum
from typing import Dict

import loopchain.utils as util
from loopchain import configure as conf
from loopchain.blockchain import get_tx_hash_generator

from . import TransactionInvalidParamError


class TransactionStatus(Enum):
    unconfirmed = 1
    confirmed = 2


class TransactionType(Enum):
    general = 1
    peer_list = 2


class TransactionStatusInQueue(Enum):
    normal = 1
    fail_validation = 2
    fail_invoke = 3
    added_to_block = 4
    precommited_to_block = 5


class CustomEncoder(json.JSONEncoder):
    def default(self, obj):
        if not hasattr(obj, '__dict__'):
            return None
        else:
            return obj.__dict__


def decode_object(obj):
    if '__Transaction__' in obj:
        tx = Transaction()
        tx.__dict__.update(obj['__Transaction__'])
        return tx
    return obj


class Transaction:
    """Transaction 거래 내용
    Peer에서 데이터를 받으면 새로운 트랜잭션을 생성하며, 생성된 트랜잭션은
    바로 BlockGenerator 에게 전달 된다
    """
    METHOD_KEY = 'method'
    PEER_ID_KEY = 'peer_id'
    SCORE_ID_KEY = 'score_id'
    SCORE_VERSION_KEY = 'score_version'
    SEND_TX_TYPE_KEY = 'send_tx_type'
    CHANNEL_KEY = 'channel_name'

    def __init__(self):
        self.__transaction_status = TransactionStatus.unconfirmed
        self.__transaction_type = TransactionType.general
        self.__meta = collections.OrderedDict()  # peer_id, score_id, score_ver ...
        self.__data = []
        self.__time_stamp = 0
        self.__transaction_hash = ""
        self.__public_key = b""
        self.__signature: bytes = b""
        self.__icx_origin_data = {}  # type: Dict[str, str]
        self.__icx_origin_data_v3 = {}  # type: Dict[str, str]
        self.__genesis_origin_data = {}  # type: Dict[str, str]
        self.__nid = None
        self.__accounts = []
        self.__message = None

    def __eq__(self, other):
        if self.tx_hash == other.tx_hash:
            return True
        else:
            return False

    def __hash__(self):
        return int(self.tx_hash, 16)

    @property
    def icx_origin_data(self):
        return self.__icx_origin_data

    @property
    def icx_origin_data_v3(self):
        return self.__icx_origin_data_v3 or self.__icx_origin_data

    @property
    def genesis_origin_data(self):
        return self.__genesis_origin_data

    def set_icx_origin_data(self, icx_origin_data: dict, dumped_data: str):
        if util.get_tx_version(icx_origin_data) == conf.ApiVersion.v3:
            return self.__set_icx_origin_data_v3(icx_origin_data, dumped_data)
        else:
            return self.__set_icx_origin_data_v2(icx_origin_data, dumped_data)

    def __set_icx_origin_data_v2(self, icx_origin_data, dumped_data):
        try:
            self.__icx_origin_data = icx_origin_data
            self.__icx_origin_data['method'] = self.__meta[Transaction.METHOD_KEY]
            self.__signature = base64.b64decode(self.__icx_origin_data['signature'].encode())
            self.__transaction_hash = self.__icx_origin_data['tx_hash']
            self.__time_stamp = int(self.__icx_origin_data.get('timestamp', 0))
            self.__data = dumped_data.encode()
            self.put_meta(self.PEER_ID_KEY, self.__icx_origin_data['from'])
            return True
        except Exception as e:
            logging.debug(f"tx {icx_origin_data['tx_hash']} create fail \n"
                          f"cause : {e}")

            raise TransactionInvalidParamError(self.__transaction_hash, icx_origin_data, str(e))

    def __set_icx_origin_data_v3(self, icx_origin_data, dumped_data):
        try:
            self.__icx_origin_data = icx_origin_data
            self.__signature = base64.b64decode(self.__icx_origin_data['signature'].encode())

            channel_name = self.meta.get(self.CHANNEL_KEY)
            hash_generator = get_tx_hash_generator(channel_name)
            self.__transaction_hash = hash_generator.generate_hash(icx_origin_data)
            self.__icx_origin_data['txHash'] = self.__transaction_hash
            self.__nid = self.__icx_origin_data['nid']
            self.__time_stamp = int(self.__icx_origin_data.get('timestamp', 0), 16)
            self.__data = dumped_data.encode()
            self.put_meta(self.PEER_ID_KEY, self.__icx_origin_data['from'])
            self.__pop_tx_hash_for_v3()
            return True
        except Exception as e:
            logging.debug(f"txHash create fail \n"
                          f"cause : {e}")

            raise TransactionInvalidParamError(self.__transaction_hash, icx_origin_data, str(e))

    def __pop_tx_hash_for_v3(self):
        self.__icx_origin_data_v3 = copy.deepcopy(self.__icx_origin_data)
        if 'txHash' in self.__icx_origin_data_v3:
            self.__icx_origin_data_v3.pop('txHash')
        return self.__icx_origin_data_v3

    def put_genesis_data(self, genesis_tx_data, tx_hash):
        try:
            self.__transaction_hash = tx_hash
            self.__genesis_origin_data = genesis_tx_data
            self.__nid = genesis_tx_data.get("nid", None)
            self.__accounts = genesis_tx_data['accounts']
            self.__message = genesis_tx_data['message']

            return True
        except Exception as e:
            logging.debug(f"genesis tx create fail \n"
                          f"cause : {e}")
            return False

    @property
    def tx_hash(self):
        return self.__transaction_hash

    @property
    def status(self):
        return self.__transaction_status

    @status.setter
    def status(self, tx_status):
        self.__transaction_status = tx_status

    @property
    def type(self):
        return self.__transaction_type

    @type.setter
    def type(self, tx_type):
        self.__transaction_type = tx_type

    @property
    def signature(self):
        return self.__signature

    @property
    def public_key(self):
        return self.__public_key

    @property
    def nid(self):
        return self.__nid

    @property
    def accounts(self):
        return self.__accounts

    @property
    def message(self):
        return self.__message

    @property
    def meta(self):
        return self.__meta.copy()

    def json_dumps(self) -> str:
        tx_wrap = {"__Transaction__": self}
        tx_json = json.dumps(tx_wrap, sort_keys=True, cls=CustomEncoder)
        return tx_json

    @staticmethod
    def json_loads(tx_json: str):
        tx_object = json.loads(tx_json, object_hook=decode_object)
        return tx_object

    def put_meta(self, key, value):
        """Tx 의 meta 정보를 구성한다.
        tx 의 put_data 발생시 tx 의 hash 를 생성하게 되며 이때 meta 정보를 hash 계산에 사용하게 되므로
        meta 정보의 구성은 put_data 이전에 완료하거나 혹은 put_data 후에 meta 정보를 추가하게 된다면
        hash 를 다시 생성하여야 한다.

        :param key:
        :param value:
        :return:
        """
        self.__meta[key] = value

    def init_meta(self, peer_id, score_id, score_ver, channel_name: str, send_tx_type: conf.SendTxType):
        """Tx 의 meta 정보 중 Peer 에 의해서 초기화되는 부분을 집약하였댜.
        tx 의 put_data 발생시 tx 의 hash 를 생성하게 되며 이때 meta 정보를 hash 계산에 사용하게 되므로
        meta 정보의 구성은 put_data 이전에 완료하거나 혹은 put_data 후에 meta 정보를 추가하게 된다면
        hash 를 다시 생성하여야 한다.

        :param peer_id:
        :param score_id:
        :param score_ver:
        :param channel_name:
        :param send_tx_type:
        :return:
        """
        self.put_meta(Transaction.PEER_ID_KEY, peer_id)
        self.put_meta(Transaction.SCORE_ID_KEY, score_id)
        self.put_meta(Transaction.SCORE_VERSION_KEY, score_ver)
        self.put_meta(Transaction.CHANNEL_KEY, channel_name)
        self.put_meta(Transaction.SEND_TX_TYPE_KEY, send_tx_type)

    def get_data(self):
        """트랜잭션 데이터를 리턴합니다.

        :return 트랜잭션 데이터:
        """
        return self.__data

    def get_data_string(self):
        return self.__data.decode(conf.PEER_DATA_ENCODING)

    def get_genesis_tx_data(self):
        # return f"{self.__transaction_hash}/{self.__god_data}/{self.__treasury_data}/{self.__message}"
        return \
            f"hash::{self.__transaction_hash}/nid::{self.__nid}/accounts::{self.__accounts}/message::{self.__message}"

    def put_data(self, data, time_stamp=None):
        """데이터 입력
        data를 받으면 해당 시간의 Time stamp와 data를 가지고 Hash를 생성해서 기록한다.

        :param data: Transaction에 넣고 싶은 data. data가 스트링인 경우 bytearray로 변환한다.
        :param time_stamp:
        :return Transaction의 data를 가지고 만든 Hash값:
        """
        if isinstance(data, str):
            self.__data = bytearray(data, 'utf-8')
        else:
            self.__data = data

        if time_stamp is None:
            self.__time_stamp = util.get_now_time_stamp()
        else:
            self.__time_stamp = time_stamp

        # logging.debug("transaction Time %s , time_stamp Type %s", self.__time_stamp, type(self.__time_stamp))

        return self.__generate_hash()

    def get_timestamp(self):
        """트랜잭션 timeStamp를 반환
        """
        return self.__time_stamp

    def __generate_hash(self):
        """트랜잭션의 hash를 생성한다.

        :return Transaction의 data를 가지고 만든 Hash값:
        """
        self.__transaction_hash = Transaction.generate_transaction_hash(self)

        # logging.debug("__generate_hash \ntx hash : " + self.__transaction_hash +
        #               "\ntx meta : " + str(self.__meta) +
        #               "\ntx data : " + str(self.__data))

        return self.__transaction_hash

    @staticmethod
    def generate_transaction_hash(tx):
        """트랜잭션 Hash 생성

        :param tx: 트랜잭션
        :return: 트랜잭션 Hash
        """
        _meta_byte = util.dict_to_binary(tx.meta)
        _data_byte = tx.get_data()
        _time_byte = struct.pack('Q', tx.get_timestamp())
        _txByte = b''.join([_meta_byte, _data_byte, _time_byte])
        _txhash = hashlib.sha256(_txByte).hexdigest()
        # logging.debug("__generate_hash \ntx hash : " + _txhash +
        #               "\ntx meta : " + str(tx.meta) +
        #               "\ntx data : " + str(tx.get_data()) +
        #               "\ntx time : " + str(_time_byte))

        return _txhash

    def sign_hash(self, peer_authorization) -> bool:
        """sign to signature hash

        :param peer_authorization: peer_authorization for sign
        :return: if sign success return true, else return false
        """
        signature = peer_authorization.sign_data(self.tx_hash, is_hash=True)
        self.__public_key = peer_authorization.tx_cert

        if signature:
            self.__signature = signature
            return True
        else:
            logging.error(f"sign transaction {self.tx_hash} fail")
            return False
