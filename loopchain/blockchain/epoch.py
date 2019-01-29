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
"""It manages the information needed during consensus to store one block height.
Candidate Blocks, Quorum, Votes and Leader Complaints.
"""
import loopchain.utils as util

from loopchain.baseservice import ObjectManager
from loopchain.blockchain import Vote
from loopchain import configure as conf


class Epoch:
    COMPLAIN_VOTE_HASH = "complain_vote_hash_for_reuse_Vote_class"

    def __init__(self, height: int, leader_id=None):
        util.logger.notice(f"New Epoch Start height({height}) leader_id({leader_id})")
        self.height = height
        self.leader_id = leader_id

        # TODO using Epoch in BlockManager instead using candidate_blocks directly.
        # But now! only collect leader complain votes.
        self.__candidate_blocks = None
        self.__complain_vote = Vote(Epoch.COMPLAIN_VOTE_HASH, ObjectManager().channel_service.peer_manager)

    @staticmethod
    def new_epoch(height: int, leader_id=None):
        leader_id = leader_id or ObjectManager().channel_service.block_manager.epoch.leader_id
        return Epoch(height, leader_id)

    def set_epoch_leader(self, leader_id):
        util.logger.notice(f"Set Epoch leader height({self.height}) leader_id({leader_id})")
        self.leader_id = leader_id

    def add_complain(self, complained_leader_id, new_leader_id, block_height, peer_id, group_id):
        util.logger.notice(f"add_complain complain_leader_id({complained_leader_id}), "
                           f"new_leader_id({new_leader_id}), "
                           f"block_height({block_height}), "
                           f"peer_id({peer_id})")
        self.__complain_vote.add_vote(group_id, peer_id, new_leader_id)

    def complain_result(self) -> str or None:
        """return new leader id when complete complain leader.

        :return: new leader id or None
        """
        vote_result = self.__complain_vote.get_result(Epoch.COMPLAIN_VOTE_HASH, conf.LEADER_COMPLAIN_RATIO)
        util.logger.notice(f"complain_result vote_result({vote_result})")

        return vote_result
