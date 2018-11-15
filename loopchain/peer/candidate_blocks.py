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
"""Manage Candidate Blocks and its vote"""

import collections
import logging

import loopchain.utils as util
from loopchain import configure as conf
from loopchain.baseservice import ObjectManager
from loopchain.blockchain import Block
from loopchain.peer import Vote
from loopchain.channel.channel_property import ChannelProperty


class NoExistBlock(Exception):
    """해당 블럭이 존재하지 않습니다.
    """
    pass


class NotCompleteValidation(Exception):
    """해당 블럭에 대한 검증이 완료되지 않았습니다.
    """
    def __init__(self, message, block=None):
        self.message = message
        self.block = block


class InvalidatedBlock(Exception):
    """검증에 실패한 블럭입니다.
    """
    def __init__(self, message, block=None):
        self.message = message
        self.block = block


class CandidateBlocks:
    """BlockManager 가 BlockChain 에 Block 을 등록하기 전
    생성한 Block 들을 관리하는 클래스
    unconfirmed block 을 저장하고, 각 peer 로 부터 vote 된 결과를 반영한다.
    """

    def __init__(self, peer_id, channel_name):
        """
        :param voter_count: 전체 투표 가능 Peer 수의 초기값 설정, 변경시 set_voter_count 로 동기화 되어야 한다.
        """
        self.__peer_id = peer_id
        self.__channel_name = channel_name
        self.__unconfirmed_blocks = collections.OrderedDict()  # $block_hash : [$vote, $block], ... 인 Ordered Dictionary
        self.__candidate_last_block = None

    def add_unconfirmed_block(self, block):
        """Block Manager 가 주기적으로 생성한 블럭을 등록한다. 이 블럭은 각 Peer 로 전송되어 Validate vote 를 받아야 한다.

        :param block: Block Manager 가 tx 를 수집하여 주기적으로 생성한 블럭, 아직 Block Chain 의 멤버가 아니다.
        :return: unconfirmed block 을 식별하기 위한 block_hash (str)
        """
        logging.debug(f"CandidateBlocks:add_unconfirmed_block ({self.__channel_name})")
        # block 생성자의 peer_id 를 지정한다. (새로 네트워크에 참여하는 피어는 마지막 블럭의 peer_id 를 리더로 간주한다.)
        block.peer_id = self.__peer_id

        # leader 가 block 에 담을 때 이미 1 투표한 내용으로 생성한다.
        vote = Vote(block.block_hash, ObjectManager().channel_service.peer_manager)
        vote.add_vote(ChannelProperty().group_id, ChannelProperty().peer_id, None)

        self.__unconfirmed_blocks[block.block_hash] = [vote, block]
        self.__candidate_last_block = block
        return block.block_hash

    def reset_voter_count(self, block_hash):
        logging.debug(f"({self.__channel_name}) Reset voter count in candidate blocks")
        vote = Vote(block_hash, ObjectManager().channel_service.peer_manager)
        prev_vote, block = self.__unconfirmed_blocks[block_hash]
        # vote.get_result_detail(block.block_hash, conf.VOTING_RATIO)
        # prev_vote.get_result_detail(block.block_hash, conf.VOTING_RATIO)
        vote.set_vote_with_prev_vote(prev_vote)
        # vote.get_result_detail(block.block_hash, conf.VOTING_RATIO)
        self.__unconfirmed_blocks[block_hash] = [vote, block]
        # logging.debug("candidate_blocks::reset_voter_count block_hash(" + block_hash + ")")

    def get_last_block(self, blockchain=None):
        last_block = blockchain.last_block if blockchain else None
        last_block = last_block or self.__candidate_last_block

        if last_block is None:
            return None

        candidate_block = self.__candidate_last_block or last_block
        return last_block if last_block.height > candidate_block.height else candidate_block

    def set_last_block(self, block):
        # self.__unconfirmed_blocks = collections.OrderedDict()
        # $block_hash : [$vote, $block], ... 인 Ordered Dictionary
        self.__candidate_last_block = block

    def vote_to_block(self, block_hash, is_validate, peer_id, group_id):
        """각 Peer 로 부터 전송된 vote 값을 Block 에 반영한다.

        :param is_validate: 검증 성공 값 (True | False)
        """
        if block_hash in self.__unconfirmed_blocks.keys():
            self.__unconfirmed_blocks[block_hash][0].add_vote(group_id, peer_id,
                                                              (conf.TEST_FAIL_VOTE_SIGN, None)[is_validate])

    def remove_broken_block(self, block_hash):
        """실패한 block 을 candidate blocks 에서 제외 한다.

        :return: 실패한 block Object
        """

        remove_block = self.__unconfirmed_blocks.pop(block_hash)[1]

        # refresh next_block's prev_hash
        prev_block: Block = None
        curr_block: Block = None  # It's for type hint
        for curr_block in self.__unconfirmed_blocks.values():
            if curr_block.prev_block_hash == block_hash:
                if prev_block:
                    curr_block.prev_block_hash = prev_block.block_hash
                else:
                    block_manager = ObjectManager().channel_service.block_manager
                    block_chain = block_manager.get_blockchain()
                    curr_block.prev_block_hash = block_chain.last_block.block_hash
                break
            prev_block = curr_block

        return remove_block

    def get_confirmed_block(self, block_hash=None):
        """검증에 성공한 block 을 얻는다.
        해당 블럭은 CandidateBlocks 에서 제거된다.

        :return: 검증에 성공한 block(이 block 은 BlockChain 에 추가되어야 한다.),
                 해당 block 이 검증되지 않았을때에는 Exception(해당블럭이 없다, 해당블럭이 아직 검증되지 않았다.) 을 발생한다.
        """
        if block_hash is None:
            candidate_block: Block = self.get_candidate_block()
            if candidate_block is None:
                return None
            block_hash = candidate_block.block_hash

        if block_hash not in self.__unconfirmed_blocks.keys():
            util.apm_event(self.__peer_id, {
                'event_type': 'NoExistBlock',
                'peer_id': self.__peer_id,
                'peer_name': conf.PEER_NAME,
                'channel_name': self.__channel_name,
                'data': {
                    'message': 'No Exist block in candidate blocks by hash',
                    'block_hash': block_hash}})
            raise NoExistBlock("No Exist block in candidate blocks by hash: " + block_hash)

        if self.__unconfirmed_blocks[block_hash][0].get_result(block_hash, conf.VOTING_RATIO):
            logging.info("Confirmed block pop from candidate blocks hash: " + block_hash)
            return self.__unconfirmed_blocks.pop(block_hash)[1]
        else:
            if self.__unconfirmed_blocks[block_hash][0].is_failed_vote(block_hash, conf.VOTING_RATIO):
                logging.warning("This block fail to validate!!")
                # ObjectManager().peer_service\
                #     .score_remove_precommit_state(self.__channel_name,
                #                                   block_height=self.__unconfirmed_blocks[block_hash][1].height,
                #                                   block_hash=block_hash)
                self.remove_broken_block(block_hash)
                util.apm_event(self.__peer_id, {
                    'event_type': 'InvalidatedBlock',
                    'peer_id': self.__peer_id,
                    'peer_name': conf.PEER_NAME,
                    'channel_name': self.__channel_name,
                    'data': {
                        'message': 'This block fail to validate',
                        'block_hash': candidate_block.block_hash}})
                raise InvalidatedBlock("This block fail to validate", candidate_block)
            else:
                logging.warning(f"There is Not Complete Validation. hash({candidate_block.block_hash})")
                util.apm_event(self.__peer_id, {
                    'event_type': 'NotCompleteValidation',
                    'peer_id': self.__peer_id,
                    'peer_name': conf.PEER_NAME,
                    'channel_name': self.__channel_name,
                    'data': {
                        'message': 'There is Not Complete Validation.',
                        'block_hash': candidate_block.block_hash}})
                raise NotCompleteValidation("Not Complete Validation", candidate_block)

    def get_candidate_block(self):
        """생성된 블록중 가장 먼저 입력된 블록을 가져온다.

        :return: block, broadcast 를 통해 피어로부터 검증 받아야 한다.
        """
        if self.__unconfirmed_blocks.__len__() > 0:
            return list(self.__unconfirmed_blocks.items())[0][1][1]

        return None

    def is_remain_blocks(self):
        return self.__unconfirmed_blocks.__len__() > 0
