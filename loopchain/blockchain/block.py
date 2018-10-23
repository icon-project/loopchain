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
"""A module for managing Score"""

import base64
import copy
import hashlib
import json
import pickle
import struct
from enum import Enum

from ordered_set import OrderedSet

from loopchain import configure as conf
from loopchain import utils as util
from loopchain.baseservice import ScoreResponse, ObjectManager
from loopchain.blockchain import TransactionStatus, Transaction
from loopchain.blockchain.exception import *
from loopchain.blockchain.score_base import *
from loopchain.blockchain.validator import get_tx_validator, get_genesis_tx_validator


class BlockStatus(Enum):
    unconfirmed = 1
    confirmed = 2


class BlockType(Enum):
    general = 1
    vote = 2
    peer_list = 3


class Block:
    """Blockchain 의 Block
    Transaction 들을 담아서 Peer들과 주고 받는 Block Object.
    """

    def __init__(self, channel_name, made_block_count=0, is_divided_block=False):
        # Block head
        self.version = "0.1a"
        self.prev_block_hash = ""
        self.prev_block_confirm = False  # SiEver 구현을 위한 값, AnnounceConfirmedBlock 메시지를 대체하여 다음 블럭에 투표 결과를 담아서 전송한다.
        self.merkle_tree_root_hash = ""
        self.merkle_tree = []
        self.time_stamp = 0
        self.__channel_name = channel_name

        # 검증된 트랜젝션 목록
        self.confirmed_transaction_list = OrderedSet()
        self.block_hash = ""
        self.height = -1
        self.block_status = BlockStatus.unconfirmed
        self.__block_type = BlockType.general

        self.peer_id = ""
        self.__made_block_count = made_block_count
        self.__is_divided_block = is_divided_block
        self.__next_leader_peer_id = ""
        self.__peer_manager = None
        self.__signature = b''
        self.__json_data = {}
        self.__commit_state = {}

    @property
    def confirmed_tx_hash_list(self):
        return [tx.tx_hash for tx in self.confirmed_transaction_list]

    @property
    def confirmed_tx_len(self):
        return len(self.confirmed_transaction_list)

    def get_confirmed_tx_hash_by_index(self, index):
        return self.confirmed_transaction_list[index].tx_hash

    def get_confirmed_tx_by_index(self, index):
        return self.confirmed_transaction_list[index]

    @property
    def commit_state(self):
        return self.__commit_state

    @commit_state.setter
    def commit_state(self, commit_state: dict):
        self.__commit_state = commit_state

    @property
    def json_data(self):
        return self.__json_data

    def get_json_data(self) -> str:
        self.__json_data = {
            "version": self.version,
            "prev_block_hash": self.prev_block_hash,
            "merkle_tree_root_hash": self.merkle_tree_root_hash,
            "time_stamp": self.time_stamp,
            "confirmed_transaction_list": [tx.icx_origin_data for tx in self.confirmed_transaction_list],
            "block_hash": self.block_hash,
            "height": self.height,
            "peer_id": self.peer_id,
            "signature": base64.b64encode(self.signature).decode(),
            "commit_state": self.__commit_state,
            "next_leader_peer_id": self.__next_leader_peer_id
        }
        return json.dumps(self.__json_data)

    def get_json_data_for_genesis(self) -> str:
        self.__json_data = {
            "version": self.version,
            "prev_block_hash": self.prev_block_hash,
            "merkle_tree_root_hash": self.merkle_tree_root_hash,
            "time_stamp": self.time_stamp,
            "confirmed_transaction_list": [tx.genesis_origin_data for tx in self.confirmed_transaction_list],
            "block_hash": self.block_hash,
            "height": self.height,
            "peer_id": self.peer_id,
            "signature": base64.b64encode(self.signature).decode(),
            "commit_state": self.__commit_state,
            "next_leader_peer_id": self.__next_leader_peer_id
        }
        return json.dumps(self.__json_data)

    @property
    def channel_name(self):
        return self.__channel_name

    @property
    def block_type(self):
        return self.__block_type

    @block_type.setter
    def block_type(self, block_type):
        if block_type is not BlockType.general:
            self.__made_block_count -= 1

        self.__block_type = block_type

    @property
    def made_block_count(self):
        return self.__made_block_count

    @property
    def is_divided_block(self):
        return self.__is_divided_block

    @is_divided_block.setter
    def is_divided_block(self, value):
        self.__is_divided_block = value

    @property
    def signature(self):
        return self.__signature

    @property
    def next_leader_peer(self):
        return self.__next_leader_peer_id

    @next_leader_peer.setter
    def next_leader_peer(self, peer_id):
        self.__next_leader_peer_id = peer_id

    @property
    def peer_manager(self):
        return self.__peer_manager

    @peer_manager.setter
    def peer_manager(self, peer_manager):
        self.__peer_manager = peer_manager

    def put_transaction(self, tx, do_validate=True):
        """It's only available on leader.

        :param tx: transaction (a transaction or list)
        :param do_validate: set False while making test block
        :return: True: If success.
        """

        if type(tx) is list:
            result = True
            for t in tx:
                result &= self.put_transaction(t)
            return result
        elif not isinstance(tx, Transaction):
            logging.error(f"Not a type of Transaction, its type is: {type(tx)}")
            return False

        tx_validator = get_tx_validator(self.channel_name)
        if do_validate and not tx_validator.validate(tx):
            return False

        tx.status = TransactionStatus.confirmed

        self.confirmed_transaction_list.append(tx)
        return True

    def put_genesis_transaction(self, tx):
        """Block Generator 에서만 사용한다.
        tx는 단수 혹은 여러개 일 수 있다

        :param tx: transaction (transaction을 담고 있는 list도 처리 가능)
        :return: True: 성공적으로 담겼을 때.
        """

        if type(tx) is list:
            result = True
            for t in tx:
                result &= self.put_genesis_transaction(t)
            return result
        elif not isinstance(tx, Transaction):
            logging.error(f"Not a type of Transaction, its type is: {type(tx)}")
            return False

        if tx.status == TransactionStatus.unconfirmed:
            # transaction 검증
            # logging.debug("Transaction Hash %s", tx.tx_hash)
            genesis_validator = get_genesis_tx_validator(self.channel_name)
            if not genesis_validator.validate(tx):
                return False

        tx.status = TransactionStatus.confirmed
        self.confirmed_transaction_list.append(tx)
        return True

    @staticmethod
    def __calculate_merkle_tree_root_hash(block):
        """현재 들어온 Tx들만 가지고 Hash tree를 구성해서 merkle tree root hash 계산.

        :return: 계산된 root hash
        """

        # 머클트리 생성
        # 일단 해당 블럭에 홀수개의 트랜잭션이 있으면 마지막 트랜잭션의 Hash를 복사하여 넣어줍니다.
        # 바로 앞의 HASH(n) + HASH(n+1) 을 해싱해 줍니다.
        # 1개가 나올때까지 반복 합니다.
        # 마지막 1개가 merkle_tree_root_hash

        block.merkle_tree_root_hash = ''
        mt_list = block.confirmed_tx_hash_list
        # block.merkle_tree.extend(mt_list)

        while True:
            tree_length = len(mt_list)
            tmp_mt_list = []
            if tree_length <= 1:
                # 0이나 1은 종료
                break
            elif tree_length % 2 == 1:
                mt_list.append(mt_list[tree_length-1])
                tree_length += 1

            # 머클해쉬 생성
            for row in range(int(tree_length/2)):
                idx = row * 2
                mk_sum = b''.join([mt_list[idx].encode(encoding='UTF-8'), mt_list[idx+1].encode(encoding='UTF-8')])
                mk_hash = hashlib.sha256(mk_sum).hexdigest()
                tmp_mt_list.append(mk_hash)
            mt_list = tmp_mt_list
            # block.merkle_tree.extend(mt_list)

        if len(mt_list) == 1:
            block.merkle_tree_root_hash = mt_list[0]

        return block.merkle_tree_root_hash

    def serialize_block(self) -> bytes:
        """블럭 Class serialize
        Pickle 을 사용하여 serialize 함

        :return: serialize 결과
        """
        if conf.CHANNEL_OPTION[self.channel_name]["send_tx_type"] == conf.SendTxType.icx:
            if self.height == 0:
                json_data = self.get_json_data_for_genesis()
            else:
                json_data = self.get_json_data()
            return json_data.encode('utf-8')
        else:
            return pickle.dumps(self, pickle.DEFAULT_PROTOCOL)

    def deserialize_block(self, block_dumps):
        """블럭 Class deserialize
        자기자신을 block_dumps의 data로 변환함

        :param block_dumps: deserialize 할 Block dump data
        """
        if conf.CHANNEL_OPTION[self.channel_name]["send_tx_type"] == conf.SendTxType.icx:
            dump_obj = json.loads(block_dumps)
            self.version = dump_obj['version']
            self.prev_block_hash = dump_obj['prev_block_hash']
            self.merkle_tree_root_hash = dump_obj['merkle_tree_root_hash']
            self.time_stamp = dump_obj['time_stamp']
            self.height = dump_obj['height']

            if self.height == 0:
                validator = get_genesis_tx_validator(self.channel_name)
                self.confirmed_transaction_list = []
            else:
                validator = get_tx_validator(self.channel_name)

            for tx_json in dump_obj['confirmed_transaction_list']:
                tx = validator.restore(json.dumps(tx_json))
                self.confirmed_transaction_list.append(tx)

            self.block_hash = dump_obj['block_hash']
            self.peer_id = dump_obj['peer_id']
            self.__signature = base64.b64decode(dump_obj['signature'].encode('UTF-8'))
            self.__commit_state = dump_obj['commit_state'] if 'commit_state' in dump_obj else self.__commit_state
            self.block_status = BlockStatus.confirmed
            self.__next_leader_peer_id = dump_obj['next_leader_peer_id']
        else:
            dump_obj = pickle.loads(block_dumps)
            if type(dump_obj) == Block:
                self.__dict__ = dump_obj.__dict__

    def find_transaction_index(self, transaction_hash):
        for idx, tx in enumerate(self.confirmed_transaction_list):
            if tx.tx_hash == transaction_hash:
                return idx
        return -1

    def find_tx_by_hash(self, tx_hash):
        for tx in self.confirmed_transaction_list:
            if tx.tx_hash == tx_hash:
                return tx
        return None

        # index = self.confirmed_tx_hash_list.index(tx_hash)
        # return self.confirmed_transaction_list[index]

    @staticmethod
    def validate(block) -> bool:
        """validate block and all transactions in block

        :param: block
        :param: tx_queue
        :return validate success return true
        """
        channel_service = ObjectManager().channel_service

        mk_hash_old = block.merkle_tree_root_hash
        mk_hash = Block.__calculate_merkle_tree_root_hash(block)
        if block.height == 0 and block.confirmed_tx_len == 0:
            # Genesis Block 은 검증하지 않습니다.
            return True

        if block.confirmed_tx_len > 0:
            # 머클트리 검증은 Tx가 있을때에만 합니다.
            if mk_hash != mk_hash_old:
                raise BlockInValidError('Merkle Tree Root hash is not same')

        if block.block_hash != Block.__generate_hash(block):
            raise BlockInValidError('block Hash is not same generate hash')

        leader = channel_service.peer_manager.get_leader_object()
        if not leader.cert_verifier.verify_hash(block.block_hash, block.signature):
            raise BlockInValidError('block signature invalid')

        if block.time_stamp == 0:
            raise BlockError('block time stamp is 0')

        if len(block.prev_block_hash) == 0:
            raise BlockError('Prev Block Hash not Exist')

        # Transaction Validate
        confirmed_tx_list = []
        tx_validator = get_tx_validator(block.channel_name)

        for tx in block.confirmed_transaction_list:
            if tx_validator.validate(tx):
                confirmed_tx_list.append(tx.tx_hash)
            else:
                raise BlockInValidError(f"block ({block.block_hash}) validate fails \n"
                                        f"tx {tx.tx_hash} is invalid")

        if not block.tx_validate_hash_unique(confirmed_tx_list):
            raise BlockInValidError('There is duplicated tx_hash')

        return True

    def tx_validate_hash_unique(self, confirmed_tx_list):
        block_manager = ObjectManager().channel_service.block_manager

        for confirmed_tx_hash in confirmed_tx_list:
            tx = block_manager.get_tx(confirmed_tx_hash)

            if tx is not None:
                logging.warning(f"block:tx_validate_hash_unique There is duplicated tx_hash({confirmed_tx_hash})")
                return False

        return True

    def verify_through_score_invoke(self, is_leader: bool=False):
        # Block에 속한 tx목록을 순회하면서 Invoke 실행
        is_verified = True
        invoke_results = {}

        if ObjectManager().channel_service is None:
            # all results to success
            success_result = dict(code=int(message_code.Response.success))
            invoke_results = util.create_invoke_result_specific_case(self.confirmed_transaction_list, success_result)
        else:
            try:
                origin_commit_state = copy.deepcopy(self.commit_state)
                invoke_results = ObjectManager().channel_service.score_invoke(self)

                if is_leader:
                    # set commit state as a leader while do nothing, block commit_state set by score_invoke
                    util.logger.spam(f"verify_through_score_invoke commit_state({self.commit_state})")
                else:
                    # verify commit state with leader's(origin_commit_state)
                    # this block must have leader's commit state
                    if origin_commit_state != self.commit_state:
                        logging.warning(f"block:verify_through_score_invoke fail commit state integrity!!")
                        is_verified = False
                    else:
                        util.logger.spam(f"verify_through_score_invoke commit state verified.")

                    # peer have to restore origin_commit_state.
                    # And when receive block confirm message check again origin and peer's commit state.
                    self.commit_state = copy.deepcopy(origin_commit_state)

            except Exception as e:
                # When Grpc Connection Raise Exception
                # save all result{'code': ScoreResponse.SCORE_CONTAINER_EXCEPTION, 'message': str(e)}
                logging.error(f'This error occurred while Score_invoke has failed in verify block : {e}')
                invoke_results = {}

        # util.logger.spam(f'Block::verify_through_score_invoke >>>>> invoke_results :: {invoke_results}')

        need_rebuild = False
        if not util.channel_use_icx(self.__channel_name):
            fail_list = [tx_hash for tx_hash, invoke_result in invoke_results.items()
                         if invoke_result["code"] != message_code.Response.success]

            need_rebuild = len(fail_list) > 0
            if is_leader:
                if need_rebuild:
                    for tx_hash in fail_list:
                        tx = self.find_tx_by_hash(tx_hash)
                        self.confirmed_transaction_list.discard(tx)

                    is_verified = self.confirmed_tx_len > 0
                elif conf.ALLOW_MAKE_EMPTY_BLOCK and not need_rebuild:
                    is_verified = True
            else:
                is_verified = not need_rebuild

        return is_verified, need_rebuild, invoke_results

    def generate_block(self, prev_block=None):
        """블럭을 생성한다 \n
        이전블럭을 입력하지 않으면, 제네시스 블럭으로 생성됨
        이전블럭을 입력하면 링킹된 블럭으로 생성됨
        블럭 높이와 이전 블럭 hash, 현재블럭의 hash계산, 머클트리 계산을 실행함

        :param prev_block: 이전 블럭
        :returns: 생성된 블럭 해쉬 값
        """
        try:
            util.logger.spam(f"ENGINE-303 generate_block prev_block: {prev_block.height} {prev_block.block_hash}")
        except Exception:
            pass

        if prev_block is None:
            # Genesis Block Data
            self.prev_block_hash = ""
            self.height = 0
            self.time_stamp = 0
        elif self.time_stamp == 0:
            if self.prev_block_hash == "":
                self.prev_block_hash = prev_block.block_hash
                self.height = prev_block.height + 1
            self.time_stamp = util.get_time_stamp()

        # 트랜잭션이 있을 경우 머클트리 생성
        if self.confirmed_tx_len > 0:
            Block.__calculate_merkle_tree_root_hash(self)
        self.block_hash = Block.__generate_hash(self)

        return self.block_hash

    @staticmethod
    def __generate_hash(block):
        """Block Hash 생성 \n
        HashData
         1. 트랜잭션 머클트리
         2. 타임스태프
         3. 이전블럭 해쉬

        :return: 블럭 해쉬값
        """

        # 자기 블럭에 대한 해쉬 생성
        # 자기 자신의 블럭해쉬는 블럭 생성후 추가되기 직전에 생성함
        # transaction(s), time_stamp, prev_block_hash
        block_hash_data = b''.join([block.prev_block_hash.encode(encoding='UTF-8'),
                                    block.merkle_tree_root_hash.encode(encoding='UTF-8'),
                                    struct.pack('Q', block.time_stamp)])
        if conf.CHANNEL_OPTION[block.channel_name]["send_tx_type"] == conf.SendTxType.icx:
            block_hash = hashlib.sha3_256(block_hash_data).hexdigest()
        else:
            block_hash = hashlib.sha256(block_hash_data).hexdigest()
        return block_hash

    def mk_merkle_proof(self, index):
        """Block안의 merkle tree에서 index 번째 Transaction이 merkle tree root를 구성하기 위한 나머지 node들의 hash값을 가져온다 (BITCOIN 머클트리 검증 proof 응용)

        :param index: Merkle tree안의 index 번째 Transaction.

        :return:  머클트리 검증 데이타 (transactiontransaction, siblingssiblings, blockblock)

          *  transaction: block안의 index번째 transaction의 hash
          *  siblings: 검증하기 위한 node들의 hash들.
          *  block: 원래는 block header인데 따로 빼질 않아서 self를 return.
        """

        nodes = [tx.tx_hash.encode(encoding='UTF-8') for tx in self.confirmed_transaction_list]
        if len(nodes) % 2 and len(nodes) > 2:
            nodes.append(nodes[-1])
        layers = [nodes]

        while len(nodes) > 1:
            new_nodes = []
            for i in range(0, len(nodes) - 1, 2):
                new_nodes.append(
                    hashlib.sha256(b''.join([nodes[i], nodes[i + 1]])).hexdigest().encode(encoding='UTF-8'))
            if len(new_nodes) % 2 and len(new_nodes) > 2:
                new_nodes.append(new_nodes[-1])
            nodes = new_nodes
            layers.append(nodes)
        # Sanity check, make sure merkle root is valid
        # assert nodes[0][::-1] == self.merkle_tree_root_hash
        merkle_siblings = [layers[i][(index >> i) ^ 1] for i in range(len(layers)-1)]

        return {
            "transaction": self.get_confirmed_tx_hash_by_index(index),
            "siblings": [x.decode('utf-8') for x in merkle_siblings],
            "block": self
        }

    @staticmethod
    def merkle_path(block, index):
        """머클트리 검증
        주어진 block에서 index 번째 transaction을 merkle tree를 계산해서 검증
        transaction 의 index값을 바탕으로 검증함
        :param block: 검증할 transaction이 있는 block.
        :param index: block안의 index 번째 transaction
        :return: True : 검증 완료
        """

        header = {}
        proof = block.mk_merkle_proof(index)
        header['merkle_root'] = block.merkle_tree_root_hash
        siblings = proof['siblings']
        logging.debug("SLBLINGS : %s", siblings)
        target_tx = block.get_confirmed_tx_hash_by_index(index)
        # siblings = map( lambda x: x.decode('hex'), siblings)
        siblings = [x.encode(encoding='UTF-8') for x in siblings]
        resulthash = target_tx.encode(encoding='UTF-8')

        for i in range(len(siblings)):
            _proof = siblings[i]
            # 0 means sibling is on the right; 1 means left
            if index % 2 == 1:
                left = _proof
                right = resulthash
            else:
                left = resulthash
                right = _proof
            resulthash = hashlib.sha256(b''.join([left, right])).hexdigest().encode(encoding='UTF-8')
            # logging.debug("%i st, %s %s => %s ", index, left, right, resulthash)
            index = int(index / 2)

        logging.debug('PROOF RESULT: %s , MK ROOT: %s', resulthash, block.merkle_tree_root_hash)

        return resulthash == block.merkle_tree_root_hash.encode(encoding='UTF-8')

    def sign(self, peer_auth):
        self.__signature = peer_auth.sign_data(self.block_hash, is_hash=True)
