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
"""An object for a phase of block """

import logging
from enum import Enum

from loopchain.blockchain import Block


class EpochStatus(Enum):
    unknown = 0
    success = 1
    leader_complain = 2


class Epoch:
    def __init__(self, **kwargs):
        self.__prev_epoch: 'Epoch' = kwargs.get("prev_epoch", None)
        self.__precommit_block: Block = kwargs.get("precommit_block", None)
        self.__block_height: int = 1 if self.__precommit_block is None else self.__precommit_block.height + 1
        self.__block_hash: str = kwargs.get("block_hash", None)
        self.__quorum: int = kwargs.get("quorum", None)
        self.__complain_quorum: int = kwargs.get("complain_quorum", None)
        self.__leader_id = kwargs.get("leader_id", None)
        self.__fixed_vote_list: dict = {}
        self.__agree_vote_list: dict = {}
        self.__complain_vote_list: dict = {}
        self.__ready_vote_list: dict = {}
        self.__status = EpochStatus.unknown

    @property
    def prev_epoch(self):
        return self.__prev_epoch

    @property
    def block_height(self):
        return self.__block_height

    @property
    def precommit_block(self):
        return self.__precommit_block

    @property
    def quorum(self):
        return self.__quorum

    @property
    def complain_quorum(self):
        return self.__complain_quorum

    @property
    def status(self):
        return self.__status

    @status.setter
    def status(self, status: EpochStatus):
        self.__status = status

    @property
    def block_hash(self):
        return self.__block_hash

    @block_hash.setter
    def block_hash(self, block_hash):
        self.__block_hash = block_hash

    @property
    def leader_id(self):
        return self.__leader_id

    @property
    def fixed_vote_list(self):
        return self.__fixed_vote_list

    @fixed_vote_list.setter
    def fixed_vote_list(self, vote_list: dict):
        self.__fixed_vote_list = vote_list

    @property
    def agree_vote_list(self):
        return self.__agree_vote_list

    @agree_vote_list.setter
    def agree_vote_list(self, vote_list: dict):
        self.__agree_vote_list = vote_list

    @property
    def complain_vote_list(self):
        return self.__complain_vote_list

    @complain_vote_list.setter
    def complain_vote_list(self, vote_list: dict):
        self.__complain_vote_list = vote_list

    @property
    def ready_vote_list(self):
        return self.__ready_vote_list

    @ready_vote_list.setter
    def ready_vote_list(self, vote_list: dict):
        self.__ready_vote_list = vote_list

    def set_quorum(self, quorum: int, complain_quorum: int):
        logging.debug(f"SET QUORUM : quorum({quorum}), complain_quorum({complain_quorum})")
        self.__quorum = quorum
        self.__complain_quorum = complain_quorum

    def set_leader(self):
        pass

    def change_state(self):
        pass
