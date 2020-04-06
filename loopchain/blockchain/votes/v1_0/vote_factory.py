from lft.consensus.messages.vote import VoteFactory, VoteVerifier

import loopchain.utils as util
from loopchain.blockchain.invoke_result import InvokePool, InvokeData
from loopchain.blockchain.types import Hash32, ExternalAddress, Signature
from loopchain.crypto.hashing import build_hash_generator
from loopchain.crypto.signature import Signer
from .vote import BlockVote

hash_generator = build_hash_generator(1, "icx_vote")


class BlockVoteFactory(VoteFactory):
    def __init__(self, invoke_result_pool: InvokePool, signer):
        self._invoke_result_pool: InvokePool = invoke_result_pool
        self._signer: Signer = signer
        self._voter_id = ExternalAddress.fromhex(self._signer.address)

    def _get_signature(self, voter_id, commit_id, data_id,
                       epoch_num, state_hash, receipt_hash, round_num, timestamp) -> Signature:
        origin_data = {
            "validator": voter_id.hex_hx(),
            "timestamp": hex(timestamp),
            "blockHash": Hash32(data_id),
            "commitHash": Hash32(commit_id),
            "stateHash": state_hash,
            "receiptHash": receipt_hash,
            "epoch": epoch_num,
            "round": round_num
        }
        hash_ = Hash32(hash_generator.generate_hash(origin_data))

        return Signature(self._signer.sign_hash(hash_))

    async def create_vote(self, data_id: bytes, commit_id: bytes, epoch_num: int, round_num: int) -> BlockVote:
        data_id: Hash32

        invoke_data: InvokeData = self._invoke_result_pool.get_invoke_data(epoch_num, round_num)

        timestamp = util.get_time_stamp()
        signature = self._get_signature(
            voter_id=self._voter_id,
            commit_id=commit_id,
            data_id=data_id,
            epoch_num=epoch_num,
            state_hash=invoke_data.state_hash,
            receipt_hash=invoke_data.receipt_hash,
            round_num=round_num,
            timestamp=timestamp
        )

        vote = BlockVote(
            voter_id=self._voter_id,
            receipt_hash=invoke_data.receipt_hash,
            state_hash=invoke_data.state_hash,
            data_id=Hash32(data_id),
            commit_id=Hash32(commit_id),
            timestamp=timestamp,
            epoch_num=epoch_num,
            round_num=round_num,
            signature=signature
        )

        return vote

    def create_none_vote(self, epoch_num: int, round_num: int) -> BlockVote:
        timestamp = util.get_time_stamp()
        signature = self._get_signature(
            voter_id=self._voter_id,
            commit_id=BlockVote.NoneVote,
            data_id=BlockVote.NoneVote,
            epoch_num=epoch_num,
            state_hash=BlockVote.NoneVote,
            receipt_hash=BlockVote.NoneVote,
            round_num=round_num,
            timestamp=timestamp
        )

        return BlockVote(
            receipt_hash=BlockVote.NoneVote,
            state_hash=BlockVote.NoneVote,
            data_id=BlockVote.NoneVote,
            commit_id=BlockVote.NoneVote,
            voter_id=self._voter_id,
            timestamp=timestamp,
            epoch_num=epoch_num,
            round_num=round_num,
            signature=signature
        )

    def create_lazy_vote(self, voter_id: bytes, epoch_num: int, round_num: int) -> BlockVote:
        timestamp = util.get_time_stamp()
        signature = self._get_signature(
            voter_id=self._voter_id,
            commit_id=BlockVote.NoneVote,
            data_id=BlockVote.NoneVote,
            epoch_num=epoch_num,
            state_hash=BlockVote.NoneVote,
            receipt_hash=BlockVote.NoneVote,
            round_num=round_num,
            timestamp=timestamp
        )

        return BlockVote(
            receipt_hash=BlockVote.LazyVote,
            state_hash=BlockVote.LazyVote,
            data_id=BlockVote.LazyVote,
            commit_id=BlockVote.LazyVote,
            voter_id=self._voter_id,
            timestamp=timestamp,
            epoch_num=epoch_num,
            round_num=round_num,
            signature=signature
        )

    async def create_vote_verifier(self) -> 'VoteVerifier':
        """This is not used in library!"""
        return VoteVerifier()
