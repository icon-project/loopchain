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
"""A Acceptor module for block """

import logging
import operator

from loopchain.baseservice import ChannelProperty
from loopchain.blockchain.block import *
from loopchain.consensus import Subscriber, Consensus
from loopchain.consensus.epoch import *
from loopchain.consensus.vote_message import *

# Changing the import location will cause a pickle error.
import loopchain_pb2

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from loopchain.channel.channel_service import ChannelService


class AcceptorStatus(IntEnum):
    normal = 0
    complain = 1
    ready = 2


class Acceptor(Subscriber):
    def __init__(self,
                 name: str,
                 channel: str, peer_id: str,
                 channel_service: 'ChannelService',
                 consensus: Consensus,
                 **kwargs):
        Subscriber.__init__(self, name)
        self.__channel = channel
        self.__channel_service: 'ChannelService' = channel_service
        self.__peer_id = peer_id
        self.__consensus = consensus
        self.__prev_epoch: Epoch = kwargs.get("prev_epoch", None)
        self.__precommit_block: Block = kwargs.get("precommit_block", None)
        self.__epoch: Epoch = kwargs.get("epoch", None)
        self.__vote_list: dict = {}
        self.__complain_list: dict = {}
        self.__ready_list: dict = {}
        self.__vote_count: dict = {}
        self.__complain_count: dict = {}
        self.__ready_count: dict = {}
        self.__uncommit_block = None
        self.__status = AcceptorStatus.normal
        self._event_list = [(Consensus.EVENT_COMPLETE_CONSENSUS, self.__callback_complete_consensus)]

    @property
    def epoch(self):
        return self.__epoch

    def __vote_precommit_block(self, vote: VoteMessage):
        logging.debug(f"Acceptor:__vote_precommit_block ({self.__channel})/({vote.type})")

        vote.sign(self.__channel_service.peer_auth)
        block_vote = loopchain_pb2.Vote(vote_code=vote.type,
                                        vote_data=vote.get_vote_data(),
                                        channel=self.__channel,
                                        peer_id=self.__peer_id)

        self.__channel_service.broadcast_scheduler.schedule_broadcast("BroadcastVote", block_vote)

    def __generate_hash(self, block: Block):
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

    def __validate_block(self, block: Block, precommit_block: Block, prev_epoch: Epoch):
        """validate block and all transactions in block

        :param: block
        :param: tx_queue
        :return validate success return true
        """

        block_manager = self.__channel_service.block_manager
        if block.height > precommit_block.height + 1:
            logging.debug(f"Acceptor: __validate_block:: do block height sync - "
                          f"epoch.height({self.__epoch.block_height})/block.height({block.height})")
            result, future = block_manager.block_height_sync()
            if result:
                future.result()
            return None
        elif self.__epoch.block_height > block.height:
            return None

        if block.height < precommit_block.height + 1:
            logging.debug("Acceptor: __validate_block:: block is already confirmed.")
            return False

        if block.height > precommit_block.height + 1:
            logging.debug(f"Acceptor: __validate_block:: do block height sync - "
                          f"precommit_block.height({precommit_block.height})/block.height({block.height})")
            result, future = block_manager.block_height_sync()
            if result:
                future.result()
                # self.__precommit_block = blockchain.get_precommit_block()

            return None

        if block.peer_id != self.__epoch.leader_id:
            logging.debug("Acceptor: __validate_block:: The block was made by another leader. "
                          "That's why it can't be validated.block leader "
                          "{block.peer_id}/ epoch leader{self.__epoch.leader_id}")
            return False

        util.logger.spam(f"try to stop timer in __validate_block")
        self.__channel_service.timer_service.stop_timer(key=f"{self.__peer_id}:{precommit_block.height}")

        return Block.validate(block)

    async def __add_success_vote(self, vote: VoteMessage):
        if vote.peer_id not in list(self.__vote_list.keys()):
            self.__vote_list[vote.peer_id] = vote

        success_count = len(self.__vote_list)
        logging.debug(f"Acceptor:__add_vote::agree: {success_count} "
                      f"complain: {len(self.__complain_list)} "
                      f"ready: {len(self.__ready_list)}")
        logging.debug(f"vote_count: {success_count} quorum: {self.__epoch.quorum}")
        util.logger.spam(f"AcceptorStatus:{self.__status}")

        if success_count >= self.__epoch.quorum:
            util.logger.spam(f"acceptor:__add_success_vote::vote count over quorum !! can make block.")
            self.__epoch.status = EpochStatus.success
            self.__epoch.agree_vote_list = self.__vote_list
            await self.__channel_service.reset_leader(
                new_leader_id=self.__consensus.precommit_block.next_leader_peer,
                block_height=self.__consensus.precommit_block.height
            )
            self.__consensus.change_epoch(prev_epoch=self.__epoch, precommit_block=self.__uncommit_block)

    def __add_leader_complain(self, vote: VoteMessage):
        if vote.peer_id not in list(self.__complain_list.keys()):
            self.__complain_list[vote.peer_id] = vote

        complain_count = len(self.__complain_list)
        logging.debug(f"Acceptor:__add_leader_complain::agree: {len(self.__vote_list)} "
                      f"complain: {complain_count} "
                      f"ready: {len(self.__ready_list)}")
        logging.debug(f"complain_count: {complain_count} quorum: {self.__epoch.complain_quorum}")
        util.logger.spam(f"Complain vote list:{self.__complain_list}")
        util.logger.spam(f"AcceptorStatus:{self.__status}")

        if self.__status != AcceptorStatus.ready:
            if complain_count >= self.__epoch.quorum:
                logging.debug(f"Acceptor:add_leader_complain::--Vote LeaderReady--")
                self.__status = AcceptorStatus.ready
                ready_vote = VoteMessage(vote_type=VoteMessageType.leader_ready,
                                         block_height=vote.block_height,
                                         leader_id=self.__consensus.leader_id,
                                         block_hash=vote.block_hash,
                                         peer_id=ChannelProperty().peer_id,
                                         channel_name=ChannelProperty().name)
                ready_vote.sign(self.__channel_service.peer_auth)
                self.__vote_precommit_block(ready_vote)
            elif complain_count >= self.__epoch.complain_quorum \
                    and self.__peer_id not in self.__complain_list:
                logging.debug(f"Acceptor:add_leader_complain::--Vote LeaderComplain because others--")
                self.__status = AcceptorStatus.complain
                complain_vote = VoteMessage(vote_type=VoteMessageType.leader_complain,
                                            block_height=vote.block_height,
                                            leader_id=self.__consensus.leader_id,
                                            block_hash=vote.block_hash,
                                            peer_id=ChannelProperty().peer_id,
                                            channel_name=ChannelProperty().name)
                self.__vote_precommit_block(complain_vote)

    def __add_leader_ready(self, vote: VoteMessage):
        if vote.peer_id not in list(self.__ready_list.keys()):
            self.__ready_list[vote.peer_id] = vote

        ready_count = len(self.__ready_list)
        logging.debug(f"Acceptor:__add_leader_ready::agree: {len(self.__vote_list)} "
                      f"complain: {len(self.__complain_list)} "
                      f"ready: {ready_count}")
        logging.debug(f"ready_count: {ready_count} quorum: {self.__epoch.quorum}")
        util.logger.spam(f"Ready vote list:{self.__ready_list}")
        util.logger.spam(f"AcceptorStatus:{self.__status}")

        if ready_count >= self.__epoch.quorum:
            self.__epoch.status = EpochStatus.leader_complain
            self.__epoch.ready_vote_list = self.__ready_list
            self.__channel_service.reset_leader(
                self.__consensus.precommit_block.next_leader_peer, self.__consensus.precommit_block.height)
            self.__consensus.change_epoch(self.__epoch, self.__epoch.precommit_block)

    def __initialize_vote_record(self):
        self.__status = AcceptorStatus.normal
        self.__vote_list.clear()
        self.__complain_list.clear()
        self.__ready_list.clear()

    def create_vote(self, block: Block, epoch: Epoch):
        util.logger.spam(f"Acceptor:create_vote:: ready to create vote")
        logging.info("Acceptor received new block for vote : " + block.block_hash)

        self.__uncommit_block = block

        precommit_block = epoch.precommit_block
        prev_epoch = epoch.prev_epoch

        try:
            block_is_validated = self.__validate_block(block, precommit_block, prev_epoch)

            if block_is_validated is not None:
                if conf.CHANNEL_OPTION[self.__channel]['store_valid_transaction_only'] and block.confirmed_tx_len > 0:
                        block_is_validated, need_rebuild, invoke_results = block.verify_through_score_invoke()
                        self.set_invoke_results(block.block_hash, invoke_results)

                if block_is_validated:
                    vote_type = VoteMessageType.success
                    leader_id = None
                else:
                    vote_type = VoteMessageType.leader_complain
                    leader_id = self.__consensus.leader_id
                    block = precommit_block
                    util.logger.spam(f"try to stop timer in create_vote")
                    self.__channel_service.timer_service.stop_timer(key=f"{self.__peer_id}:{precommit_block.height}")

                self.__vote_precommit_block(
                    VoteMessage(vote_type=vote_type,
                                block_height=block.height,
                                block_hash=block.block_hash,
                                leader_id=leader_id,
                                peer_id=self.__peer_id,
                                channel_name=ChannelProperty().name))
        except Exception as e:
            logging.error(f"Acceptor:create_vote::{e}")

    async def apply_vote_into_block(self, vote: VoteMessage, group_id=conf.PEER_GROUP_ID):
        """각 Peer 로 부터 전송된 vote 값을 Block 에 반영한다.

        :param vote:
        :param group_id:
        :return:
        """

        logging.debug(f"Acceptor:apply_vote_into_block:: Apply vote into a block.")
        logging.debug(f"======================vote({vote.block_hash})")
        logging.debug(f"======================epoch({self.__epoch.block_hash})")
        logging.debug(f"======================precommit_block({self.__epoch.precommit_block.block_hash})")

        if vote.block_height > self.__epoch.block_height:
            logging.debug(f"Acceptor: apply_vote_into_block:: do block height sync - "
                          f"epoch.height({self.__epoch.block_height})/vote.block_height({vote.block_height})")
            result, future = self.__channel_service.block_manager.block_height_sync()
            if result:
                future.result()
            return None

        if vote.type == VoteMessageType.success:
            if vote.block_hash == self.__epoch.block_hash and vote.block_height == self.__epoch.block_height:
                await self.__add_success_vote(vote)
            # elif vote.block_hash == self.__epoch.precommit_block.block_hash:
            #     logging.debug(f"Acceptor.py:apply_vote_into_block::"
            #                   f"This block already has done consensus ({vote.block_hash}/{vote.block_height})")
            else:
                logging.debug(f"This vote doesn't include same block data with that this peer is expected. "
                              f"hash({vote.block_hash}/{self.__epoch.block_hash}), "
                              f"height({vote.block_height}/{self.__epoch.block_height})")
        else:
            if vote.block_hash == self.__epoch.precommit_block.block_hash \
                    and vote.block_height == self.__epoch.precommit_block.height \
                    and vote.leader_id == self.__consensus.leader_id:
                if vote.type == VoteMessageType.leader_complain:
                    self.__add_leader_complain(vote)
                elif vote.type == VoteMessageType.leader_ready:
                    self.__add_leader_ready(vote)
            else:
                logging.debug(f"This vote doesn't include same info that this peer is expected.")
                logging.debug(f"vote hash({vote.block_hash}) height({vote.block_height}) leader({vote.leader_id})\n"
                              f"epoch hash({self.__epoch.block_hash}) height({self.__epoch.block_height}) "
                              f"leader({self.__consensus.leader_id})")

    def set_consensus_status(self):
        # update data about new epoch
        # consensus.update(epoch, precommit_block)
        pass

    def callback_leader_complain(self, **kwargs):
        epoch: Epoch = kwargs.get("epoch", None)
        util.logger.spam(f"Acceptor:callback_leader_complain:: leader_id({self.__consensus.leader_id})/"
                         f"block_hash({epoch.block_hash})")

        self.__status = AcceptorStatus.complain
        precommit_block = epoch.precommit_block
        vote = VoteMessage(vote_type=VoteMessageType.leader_complain,
                           block_height=precommit_block.height,
                           leader_id=self.__consensus.leader_id,
                           block_hash=precommit_block.block_hash,
                           peer_id=ChannelProperty().peer_id,
                           channel_name=ChannelProperty().name)

        util.logger.spam(f"acceptor.py:callback_leader_complain::try to stop timer in CALLBACK_LEADER_COMPLAIN")
        self.__channel_service.timer_service.stop_timer(key=f"{self.__peer_id}:{precommit_block.height}")
        self.__vote_precommit_block(vote)

    def __callback_complete_consensus(self, **kwargs):
        self.__prev_epoch = kwargs.get("prev_epoch", None)
        self.__precommit_block = kwargs.get("precommit_block", None)
        self.__epoch = kwargs.get("epoch", None)
        self.__initialize_vote_record()
