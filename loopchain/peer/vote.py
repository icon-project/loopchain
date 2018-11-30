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
"""data object for peer votes to one block"""

import logging

from enum import Enum

from loopchain.baseservice import PeerManager
from loopchain import configure as conf


class VoteType(Enum):
    block = 1
    leader_complain = 2


class Vote:

    def __init__(self, target_hash, audience, sign=None, vote_type=VoteType.block, data=None):
        """

        :param target_hash:
        :param audience: { peer_id : peer_info(SubscribeRequest of gRPC) }
        :param sign:
        :param vote_type:
        :return
        """

        # VoteType class
        self.__type = vote_type
        self.__target_hash = target_hash
        self.__sign = sign
        self.__data = data
        # self.__votes is { group_id : { peer_id : [vote_result, vote_sign] }, }:
        self.__votes = self.__make_vote_init(audience)

    @property
    def type(self):
        return self.__type

    @property
    def votes(self):
        return self.__votes

    @property
    def target_hash(self):
        return self.__target_hash

    @staticmethod
    def __make_vote_init(audience):
        vote_init = {}
        if isinstance(audience, PeerManager):
            for group_id in list(audience.peer_list.keys()):
                if group_id == conf.ALL_GROUP_ID:
                    continue
                vote_init[group_id] = {}
                for peer_id in list(audience.peer_list[group_id].keys()):
                    vote_init[group_id][peer_id] = []
        else:
            for peer_id in audience:
                vote_init[audience[peer_id].group_id] = {}
                vote_init[audience[peer_id].group_id][peer_id] = []

        logging.debug("vote_init: " + str(vote_init))
        return vote_init

    @staticmethod
    def __parse_vote_sign(vote_sign):
        """서명된 vote로 부터 투표 결과를 추출한다."""

        return vote_sign

    def add_vote(self, group_id, peer_id, vote_sign):
        if group_id not in self.__votes.keys():
            return False
        if peer_id not in self.__votes[group_id].keys():
            return False
        self.__votes[group_id][peer_id] = (self.__parse_vote_sign(vote_sign), vote_sign)
        return True

    def get_result(self, block_hash, voting_ratio):
        return self.get_result_detail(block_hash, voting_ratio)[0]

    def get_result_detail(self, block_hash, voting_ratio):
        """

        :param block_hash:
        :param voting_ratio:
        :return: result(True|False),
        agree_vote_group_count, total_vote_group_count, total_group_count,
        agree_vote_peer_count, total_peer_count, voting_ratio
        """

        if self.__target_hash != block_hash:
            return False, 0, 0, 0, 0, 0, 0

        total_group_count = len(self.__votes)
        total_peer_count = sum([len(self.__votes[group_id]) for group_id in list(self.__votes.keys())])
        agree_vote_group_count = 0
        total_vote_group_count = 0
        agree_vote_peer_count = 0
        result = False

        for group_id in list(self.__votes.keys()):
            # don't treat with null group
            if len(self.__votes[group_id]) == 0:
                continue

            total_peer_count_in_group = 0
            agree_peer_count_in_group = 0
            vote_peer_count_in_group = 0
            for peer_id in list(self.__votes[group_id].keys()):
                total_peer_count_in_group += 1
                if len(self.__votes[group_id][peer_id]) > 0 and self.__votes[group_id][peer_id][0] is True:
                    agree_peer_count_in_group += 1
                    agree_vote_peer_count += 1
                if len(self.__votes[group_id][peer_id]) > 0 and self.__votes[group_id][peer_id][0] is False:
                    vote_peer_count_in_group += 1

            if agree_peer_count_in_group > total_peer_count_in_group * voting_ratio:
                agree_vote_group_count += 1
                total_vote_group_count += 1
            elif (vote_peer_count_in_group - agree_peer_count_in_group) \
                    >= total_peer_count_in_group * (1 - voting_ratio):
                total_vote_group_count += 1

        if agree_vote_group_count > total_group_count * voting_ratio:
            result = True

        logging.debug("==result: " + str(result))
        logging.debug("=agree_vote_group_count: " + str(agree_vote_group_count))
        logging.debug("=total_vote_group_count: " + str(total_vote_group_count))
        logging.debug("=total_group_count: " + str(total_group_count))
        logging.debug("=agree_vote_peer_count: " + str(agree_vote_peer_count))
        logging.debug("=total_peer_count: " + str(total_peer_count))

        return result, agree_vote_group_count, total_vote_group_count, \
            total_group_count, agree_vote_peer_count, total_peer_count, voting_ratio

    def is_failed_vote(self, block_hash, voting_ratio):
        result, agree_vote_group_count, total_vote_group_count, total_group_count, \
            agree_vote_peer_count, total_peer_count, voting_ratio = self.get_result_detail(block_hash, voting_ratio)

        fail_vote_group_count = total_vote_group_count - agree_vote_group_count
        possible_agree_vote_group_count = total_group_count - fail_vote_group_count

        if possible_agree_vote_group_count > total_group_count * voting_ratio:
            # this vote still possible get consensus
            return False
        else:
            # this vote final fail
            return True

    def set_vote_with_prev_vote(self, prev_vote):
        for group_id in list(self.__votes.keys()):
            if group_id not in prev_vote.votes.keys():
                continue
            for peer_id in list(self.__votes[group_id].keys()):
                if peer_id not in prev_vote.votes[group_id].keys():
                    continue
                self.__votes[group_id][peer_id] = prev_vote.votes[group_id][peer_id]

    def check_vote_init(self, audience):
        """check leader's vote init is same on this peer

        :param audience: { peer_id : peer_info(SubscribeRequest of gRPC) } or peer_list {}
        :return:
        """

        vote_groups = list(self.__votes.keys())
        check_groups = list(self.__make_vote_init(audience).keys())
        return vote_groups.sort() == check_groups.sort()
