"""A module for managing peer list"""

import loopchain.utils as util
from loopchain import configure as conf
from loopchain.baseservice import ObjectManager
from loopchain.blockchain.types import Hash32
from loopchain.channel.channel_property import ChannelProperty
from loopchain.peermanager import PeerLoader


class PeerManager:
    def __init__(self):
        self._crep_root_hash = Hash32.fromhex(conf.CHANNEL_OPTION[ChannelProperty().name].get('crep_root_hash'))

    @property
    def crep_root_hash(self):
        return self._crep_root_hash

    def load_peers(self) -> None:
        blockchain = ObjectManager().channel_service.block_manager.blockchain
        if not blockchain.is_roothash_exist_in_db(self._crep_root_hash):
            reps_hash, reps = PeerLoader.load()
            util.logger.info(f"Initial Loaded Reps: {reps}")
            if not blockchain.is_roothash_exist_in_db(reps_hash):
                blockchain.write_preps(reps_hash, reps)
