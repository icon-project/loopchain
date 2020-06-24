"""It manages the information needed during consensus to store one block height.
Candidate Blocks, Quorum, Votes and Leader Complaints.
"""

from typing import Dict, Optional, TYPE_CHECKING

from loopchain import utils, configure as conf
from loopchain.blockchain.types import ExternalAddress
from loopchain.blockchain.votes.votes import VoteError, Votes
from loopchain.channel.channel_property import ChannelProperty

if TYPE_CHECKING:
    from loopchain.blockchain import BlockChain


class ComplainVoteManager:
    def __init__(self):
        self.complain_votes: Dict[int, 'LeaderVotes'] = {}
        self.reps_hash = None
        self.reps = []

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

    def complain_result(self, round_) -> Optional[str]:
        """return new leader id when complete complain leader.

        :return: new leader id or None
        """
        utils.logger.debug(f"complain_result vote_result({self.complain_votes[round_].get_summary()})")
        if self.complain_votes[round_].is_completed():
            vote_result = self.complain_votes[round_].get_result()
            return vote_result.hex_hx()
        else:
            return None

    def init_complain_votes(self, reps, version, height, round_, leader_id):
        leader_votes = Votes.get_leader_votes_class(version)(
            reps,
            conf.VOTING_RATIO,
            height,
            round_,
            ExternalAddress.fromhex_address(leader_id)
        )
        self.complain_votes[round_] = leader_votes


class Epoch:
    def __init__(self, reps_hash, reps, version, height=None, leader_id=None):
        self.leader_vote_manager = ComplainVoteManager()
        self.height = height + 1 if height else 1
        self.leader_id = leader_id
        utils.logger.debug(f"New Epoch Start height({self.height }) leader_id({leader_id})")

        self.round = 0
        self.complained_result = None
        utils.logger.debug(f"new round 0, {self.round}")

        self.reps_hash = None  # init by self.new_votes()
        self.reps = []  # init by self.new_votes()

        self.new_votes(reps_hash, reps, version)

    @property
    def complain_duration(self):
        return min((2 ** self.round) * conf.TIMEOUT_FOR_LEADER_COMPLAIN, conf.MAX_TIMEOUT_FOR_LEADER_COMPLAIN)

    @property
    def complain_votes(self) -> Dict[int, 'LeaderVotes']:
        return self.leader_vote_manager.complain_votes

    @classmethod
    def new(cls, blockchain: 'BlockChain', leader_id=None):
        reps_hash = blockchain.last_block.header.revealed_next_reps_hash or ChannelProperty().crep_root_hash
        reps = blockchain.find_preps_addresses_by_roothash(reps_hash)
        height = blockchain.last_block.header.height
        version = blockchain.block_versioner.get_version(height)

        return cls(
            reps_hash, reps, version, height, leader_id
        )

    def new_round(self, new_leader_id, reps_hash, reps, version):
        self._set_epoch_leader(new_leader_id)
        self.round += 1
        utils.logger.debug(f"new round {self.round-1}, {self.round}")

        self.new_votes(reps_hash, reps, version)

    def new_votes(self, reps_hash, reps, version):
        self.reps_hash = reps_hash
        self.reps = reps

        self.leader_vote_manager.init_complain_votes(self.reps, version, self.height, self.round, self.leader_id)

    def _set_epoch_leader(self, leader_id):
        utils.logger.debug(f"Set Epoch leader height({self.height}) leader_id({leader_id})")
        self.leader_id = leader_id
        if self.leader_id == ChannelProperty().peer_id:
            self.complained_result = True
        else:
            self.complained_result = None

    def add_complain(self, leader_vote: 'LeaderVote'):
        self.leader_vote_manager.add_complain(leader_vote)

    def complain_result(self) -> Optional[str]:
        return self.leader_vote_manager.complain_result(self.round)
