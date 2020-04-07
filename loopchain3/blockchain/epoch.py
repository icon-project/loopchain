"""It manages the information needed during consensus to store one block height.
Candidate Blocks, Quorum, Votes and Leader Complaints.
"""

import time
import traceback
from typing import Dict, Optional, TYPE_CHECKING

from pkg_resources import parse_version

from loopchain import utils, configure as conf
from loopchain.blockchain.blocks import BlockBuilder
from loopchain.blockchain.transactions import Transaction, TransactionVerifier
from loopchain.blockchain.types import TransactionStatusInQueue, ExternalAddress
from loopchain.blockchain.votes.votes import VoteError, Votes
from loopchain.blockchain.exception import ConsensusChanged
from loopchain.channel.channel_property import ChannelProperty

if TYPE_CHECKING:
    from loopchain.peer import BlockManager


class Epoch:
    def __init__(self, block_manager: 'BlockManager', leader_id=None):
        self.__block_manager: BlockManager = block_manager
        self.__blockchain = block_manager.blockchain
        if self.__blockchain.last_block:
            self.height = self.__blockchain.last_block.header.height + 1
        else:
            self.height = 1
        self.leader_id = leader_id
        utils.logger.debug(f"New Epoch Start height({self.height }) leader_id({leader_id})")

        # TODO using Epoch in BlockManager instead using candidate_blocks directly.
        # But now! only collect leader complain votes.
        self.__candidate_blocks = None

        self.round = 0
        self.complain_votes: Dict[int, 'LeaderVotes'] = {}
        self.complained_result = None

        self.reps_hash = None  # init by self.new_votes()
        self.reps = []  # init by self.new_votes()

        self.new_votes()
        self.new_round(leader_id, 0)

    @property
    def complain_duration(self):
        return min((2 ** self.round) * conf.TIMEOUT_FOR_LEADER_COMPLAIN, conf.MAX_TIMEOUT_FOR_LEADER_COMPLAIN)

    def new_round(self, new_leader_id, round_=None):
        is_complained = round_ != 0
        self.set_epoch_leader(new_leader_id, is_complained)

        if round_ is None:
            self.round += 1
        else:
            self.round = round_

        utils.logger.debug(f"new round {round_}, {self.round}")

        self.new_votes()

    def new_votes(self):
        self.reps_hash = self.__blockchain.last_block.header.revealed_next_reps_hash or \
                         ChannelProperty().crep_root_hash
        self.reps = self.__blockchain.find_preps_addresses_by_roothash(self.reps_hash)

        # TODO After the v0.4 update, remove this version parsing.
        if parse_version(self.__blockchain.last_block.header.version) >= parse_version("0.4"):
            ratio = conf.VOTING_RATIO
        else:
            ratio = conf.LEADER_COMPLAIN_RATIO

        version = self.__blockchain.block_versioner.get_version(self.height)
        leader_votes = Votes.get_leader_votes_class(version)(
            self.reps,
            ratio,
            self.height,
            self.round,
            ExternalAddress.fromhex_address(self.leader_id)
        )
        self.complain_votes[self.round] = leader_votes

    def set_epoch_leader(self, leader_id, complained=False):
        utils.logger.debug(f"Set Epoch leader height({self.height}) leader_id({leader_id})")
        self.leader_id = leader_id
        if complained and leader_id == ChannelProperty().peer_id:
            self.complained_result = complained
        else:
            self.complained_result = None

    def add_complain(self, leader_vote: 'LeaderVote'):
        utils.logger.debug(f"add_complain complain_leader_id({leader_vote.old_leader}), "
                           f"new_leader_id({leader_vote.new_leader}), "
                           f"block_height({leader_vote.block_height}), "
                           f"round({leader_vote.round}), "
                           f"peer_id({leader_vote.rep})")
        try:
            self.complain_votes[leader_vote.round].add_vote(leader_vote)
        except KeyError as e:
            utils.logger.warning(f"{e}\nThere is no vote of {leader_vote.round} round.")
        except VoteError as e:
            utils.logger.info(e)
        except RuntimeError as e:
            utils.logger.warning(e)

    def complain_result(self) -> Optional[str]:
        """return new leader id when complete complain leader.

        :return: new leader id or None
        """
        utils.logger.debug(f"complain_result vote_result({self.complain_votes[self.round].get_summary()})")
        if self.complain_votes[self.round].is_completed():
            vote_result = self.complain_votes[self.round].get_result()
            return vote_result.hex_hx()
        else:
            return None

    def __add_tx_to_block(self, block_builder):
        tx_queue = self.__block_manager.get_tx_queue()

        block_tx_size = 0
        tx_versioner = self.__blockchain.tx_versioner
        while tx_queue:
            if block_tx_size >= conf.MAX_TX_SIZE_IN_BLOCK:
                utils.logger.warning(
                    f"consensus_base total size({block_builder.size()}) "
                    f"count({len(block_builder.transactions)}) "
                    f"_txQueue size ({len(tx_queue)})")
                break

            tx: 'Transaction' = tx_queue.get_item_in_status(
                get_status=TransactionStatusInQueue.normal,
                set_status=TransactionStatusInQueue.added_to_block
            )
            if tx is None:
                break

            block_timestamp = block_builder.fixed_timestamp
            if not utils.is_in_time_boundary(tx.timestamp, conf.TIMESTAMP_BOUNDARY_SECOND, block_timestamp):
                utils.logger.info(f"fail add tx to block by TIMESTAMP_BOUNDARY_SECOND"
                                  f"({conf.TIMESTAMP_BOUNDARY_SECOND}) "
                                  f"tx({tx.hash}), timestamp({tx.timestamp})")
                continue

            tv = TransactionVerifier.new(tx.version, tx.type(), tx_versioner)

            try:
                tv.verify(tx, self.__blockchain)
            except Exception as e:
                utils.logger.warning(
                    f"tx hash invalid.\n"
                    f"tx: {tx}\n"
                    f"exception: {e}"
                )
                traceback.print_exc()
            else:
                block_builder.transactions[tx.hash] = tx
                block_tx_size += tx.size(tx_versioner)

    def remove_duplicate_tx_when_turn_to_leader(self):
        if self.__blockchain.last_unconfirmed_block and \
                self.__blockchain.last_unconfirmed_block.header.peer_id != ChannelProperty().peer_address:
            tx_queue = self.__block_manager.get_tx_queue()

            for tx_hash_in_unconfirmed_block in self.__blockchain.last_unconfirmed_block.body.transactions:
                try:
                    tx_queue.set_item_status(
                        tx_hash_in_unconfirmed_block.hex(),
                        TransactionStatusInQueue.added_to_block)
                except KeyError:
                    continue
            utils.logger.spam(f"There is no duplicated tx anymore.")

    def makeup_block(self,
                     complain_votes: 'LeaderVotes',
                     prev_votes,
                     new_term: bool = False,
                     skip_add_tx: bool = False):
        last_block = self.__blockchain.last_unconfirmed_block or self.__blockchain.last_block
        block_height = last_block.header.height + 1
        block_version = self.__blockchain.block_versioner.get_version(block_height)
        block_builder = BlockBuilder.new(block_version, self.__blockchain.tx_versioner)
        block_builder.fixed_timestamp = int(time.time() * 1_000_000)
        block_builder.prev_votes = prev_votes
        if complain_votes and complain_votes.get_result():
            block_builder.leader_votes = complain_votes.votes

        if new_term:
            block_builder.next_leader = None
            block_builder.reps = None
        elif skip_add_tx:
            utils.logger.debug(f"skip_add_tx for block height({self.height})")
        else:
            self.__add_tx_to_block(block_builder)

        return block_builder
