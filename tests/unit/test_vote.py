#!/usr/bin/env python
# -*- coding: utf-8 -*-

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
"""Test Vote Object"""
import hashlib
import logging
import os
import unittest

import tests.unit.test_util as test_util
from loopchain.blockchain.types import ExternalAddress, Hash32, Signature
from loopchain.blockchain.votes import vote, votes
from loopchain.blockchain.votes.v0_1a import BlockVote, BlockVotes, LeaderVote, LeaderVotes
from loopchain.crypto.signature import Signer
from loopchain.utils import loggers

loggers.set_preset_type(loggers.PresetType.develop)
loggers.update_preset()


class TestVote(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signers = [Signer.from_prikey(os.urandom(32)) for _ in range(100)]
        cls.reps = [ExternalAddress.fromhex_address(signer.address) for signer in cls.signers]

    def setUp(self):
        test_util.print_testname(self._testMethodName)

    def test_block_vote(self):
        signer = self.signers[0]
        block_hash = Hash32(os.urandom(Hash32.size))
        block_vote = BlockVote.new(signer, 0, 0, 0, block_hash)
        block_vote.verify()

        origin = f"icx_vote.blockHash.{block_vote.block_hash.hex_0x()}.blockHeight.{hex(block_vote.block_height)}."
        origin += f"rep.{block_vote.rep.hex_hx()}.round_.{block_vote.round_}.timestamp.{hex(block_vote.timestamp)}"

        origin_data = block_vote.to_origin_data(**block_vote.origin_args())
        self.assertEqual(origin, vote.hash_generator.generate_salted_origin(origin_data))

        self.assertEqual(Hash32(hashlib.sha3_256(origin.encode('utf-8')).digest()),
                         block_vote.to_hash(**block_vote.origin_args()))

    def test_block_votes_true(self):
        ratio = 0.67
        block_hash = Hash32(os.urandom(Hash32.size))
        block_votes = BlockVotes(self.reps, ratio, 0, 0, block_hash)

        for i, signer in enumerate(self.signers):
            if i == 66:
                break

            block_vote = BlockVote.new(signer, 0, 0, 0, block_hash)
            block_votes.add_vote(block_vote)

        self.assertEqual(block_votes.quorum, len(self.reps) * ratio)
        logging.info(block_votes)

        self.assertEqual(block_votes.is_completed(), False)
        self.assertEqual(block_votes.get_result(), None)

        block_vote = BlockVote.new(self.signers[99], 0, 0, 0, block_hash)
        block_votes.add_vote(block_vote)

        self.assertEqual(block_votes.is_completed(), True)
        self.assertEqual(block_votes.get_result(), True)

    def test_block_votes_false(self):
        ratio = 0.67
        block_hash = Hash32(os.urandom(Hash32.size))
        block_votes = BlockVotes(self.reps, ratio, 0, 0, block_hash)

        for i, signer in enumerate(self.signers):
            if i % 4 == 0:
                block_vote = BlockVote.new(signer, 0, 0, 0, block_hash)
            else:
                block_vote = BlockVote.new(signer, 0, 0, 0, Hash32.empty())
            block_votes.add_vote(block_vote)

        logging.info(block_votes)
        self.assertEqual(block_votes.quorum, len(self.reps) * ratio)
        self.assertEqual(block_votes.get_result(), False)

    def test_block_votes_fail(self):
        ratio = 0.67
        block_hash = Hash32(os.urandom(Hash32.size))
        block_votes = BlockVotes(self.reps, ratio, 0, 0, block_hash)

        for i, signer in enumerate(self.signers):
            if i == 33:
                break

            block_vote = BlockVote.new(signer, 0, 0, 0, Hash32.empty())
            block_votes.add_vote(block_vote)

        self.assertEqual(block_votes.quorum, len(self.reps) * ratio)

        logging.info(block_votes)
        self.assertEqual(block_votes.is_completed(), False)
        self.assertEqual(block_votes.get_result(), None)

        block_vote = BlockVote.new(self.signers[99], 0, 0, 0, Hash32.empty())
        block_votes.add_vote(block_vote)

        logging.info(block_votes)
        self.assertEqual(block_votes.is_completed(), True)
        self.assertEqual(block_votes.get_result(), False)

    def test_block_votes_completed(self):
        ratio = 0.67
        block_hash = Hash32(os.urandom(Hash32.size))
        block_votes = BlockVotes(self.reps, ratio, 0, 0, block_hash)

        signers = list(enumerate(self.signers))
        for i, signer in signers[:25]:
            block_vote = BlockVote.new(signer, 0, 0, 0, block_hash)
            block_votes.add_vote(block_vote)

        logging.info(block_votes)
        self.assertEqual(block_votes.is_completed(), False)
        self.assertEqual(block_votes.get_result(), None)

        for i, signer in signers[25:50]:
            block_vote = BlockVote.new(signer, 0, 0, 0, block_hash)
            block_votes.add_vote(block_vote)

        logging.info(block_votes)
        self.assertEqual(block_votes.is_completed(), False)
        self.assertEqual(block_votes.get_result(), None)

        for i, signer in signers[50:75]:
            block_vote = BlockVote.new(signer, 0, 0, 0, Hash32.empty())
            block_votes.add_vote(block_vote)

        logging.info(block_votes)
        self.assertEqual(block_votes.is_completed(), False)
        self.assertEqual(block_votes.get_result(), None)

        for i, signer in signers[75:90]:
            block_vote = BlockVote.new(signer, 0, 0, 0, Hash32.empty())
            block_votes.add_vote(block_vote)

        logging.info(block_votes)
        self.assertEqual(block_votes.is_completed(), True)
        self.assertEqual(block_votes.get_result(), False)

    def test_block_invalid_vote(self):
        ratio = 0.67
        block_hash = Hash32(os.urandom(Hash32.size))
        block_votes = BlockVotes(self.reps, ratio, 0, 0, block_hash)

        invalid_block_vote = BlockVote.new(self.signers[0], 0, 0, 1, block_hash)
        self.assertRaises(RuntimeError, block_votes.add_vote, invalid_block_vote)

        invalid_block_vote = BlockVote.new(self.signers[0], 0, 1, 0, block_hash)
        self.assertRaises(RuntimeError, block_votes.add_vote, invalid_block_vote)

        invalid_block_vote = BlockVote.new(self.signers[0], 0, 0, 0, Hash32(os.urandom(32)))
        self.assertRaises(RuntimeError, block_votes.add_vote, invalid_block_vote)

        invalid_block_vote = BlockVote(rep=self.reps[0], timestamp=0, signature=Signature(os.urandom(65)),
                                       block_height=0, round_=0, block_hash=block_hash)
        self.assertRaises(RuntimeError, block_votes.add_vote, invalid_block_vote)

        block_vote = BlockVote.new(self.signers[0], 0, 0, 0, block_hash)
        block_votes.add_vote(block_vote)
        duplicate_block_vote = BlockVote.new(self.signers[0], 0, 0, 0, Hash32.empty())
        self.assertRaises(votes.VoteDuplicateError, block_votes.add_vote, duplicate_block_vote)

    def test_leader_vote(self):
        signer = self.signers[0]
        leader_vote = LeaderVote.new(signer, 0, 0, 0, self.reps[0], self.reps[1])
        leader_vote.verify()

        origin = f"icx_vote.blockHeight.{hex(leader_vote.block_height)}."
        origin += f"newLeader.{leader_vote.new_leader.hex_hx()}.oldLeader.{leader_vote.old_leader.hex_hx()}."
        origin += f"rep.{leader_vote.rep.hex_hx()}.round_.{leader_vote.round_}.timestamp.{hex(leader_vote.timestamp)}"

        origin_data = leader_vote.to_origin_data(**leader_vote.origin_args())
        print(str(vote.hash_generator.generate_salted_origin(origin_data)))
        self.assertEqual(origin, vote.hash_generator.generate_salted_origin(origin_data))

        self.assertEqual(Hash32(hashlib.sha3_256(origin.encode('utf-8')).digest()),
                         leader_vote.to_hash(**leader_vote.origin_args()))

    def test_leader_votes(self):
        ratio = 0.67
        old_leader = self.reps[0]
        new_leaders = [
            self.reps[1],
            self.reps[2],
            self.reps[3],
            self.reps[4]
        ]

        leader_votes = LeaderVotes(self.reps, ratio, 0, 0, old_leader)
        for i, (rep, signer) in enumerate(zip(self.reps, self.signers)):
            mod = i % 10
            if mod < 1:
                new_leader = new_leaders[1]
            elif mod < 2:
                new_leader = new_leaders[2]
            elif mod < 3:
                new_leader = new_leaders[3]
            else:
                new_leader = new_leaders[0]
            leader_vote = LeaderVote.new(signer, 0, 0, 0, old_leader, new_leader)
            leader_votes.add_vote(leader_vote)

        logging.info(leader_votes)
        self.assertEqual(leader_votes.is_completed(), True)
        self.assertEqual(leader_votes.get_result(), new_leaders[0])

    def test_leader_votes_completed(self):
        ratio = 0.67
        old_leader = self.reps[0]
        new_leaders = [
            self.reps[1],
            self.reps[2]
        ]

        leader_votes = LeaderVotes(self.reps, ratio, 0, 0, old_leader)
        for i, (rep, signer) in enumerate(zip(self.reps[:25], self.signers[:25])):
            new_leader = new_leaders[0]
            leader_vote = LeaderVote.new(signer, 0, 0, 0, old_leader, new_leader)
            leader_votes.add_vote(leader_vote)

        self.assertEqual(leader_votes.is_completed(), False)
        self.assertEqual(leader_votes.get_result(), None)

        for i, (rep, signer) in enumerate(zip(self.reps[25:50], self.signers[25:50])):
            new_leader = new_leaders[1]
            leader_vote = LeaderVote.new(signer, 0, 0, 0, old_leader, new_leader)
            leader_votes.add_vote(leader_vote)

        self.assertEqual(leader_votes.is_completed(), False)
        self.assertEqual(leader_votes.get_result(), None)

        for i, (rep, signer) in enumerate(zip(self.reps[50:75], self.signers[50:75])):
            new_leader = new_leaders[0]
            leader_vote = LeaderVote.new(signer, 0, 0, 0, old_leader, new_leader)
            leader_votes.add_vote(leader_vote)

        self.assertEqual(leader_votes.is_completed(), False)
        self.assertEqual(leader_votes.get_result(), None)

        for i, (rep, signer) in enumerate(zip(self.reps[75:90], self.signers[75:90])):
            new_leader = new_leaders[1]
            leader_vote = LeaderVote.new(signer, 0, 0, 0, old_leader, new_leader)
            leader_votes.add_vote(leader_vote)

        self.assertEqual(leader_votes.is_completed(), True)
        self.assertEqual(leader_votes.get_result(), None)

    def test_leader_votes_completed_with_out_of_round(self):
        ratio = 0.51
        old_leader = self.reps[0]
        next_leader = self.reps[1]
        by_higher_rounder = ExternalAddress.empty()

        leader_votes = LeaderVotes(self.reps, ratio, 0, 0, old_leader)
        for i, (rep, signer) in enumerate(zip(self.reps[:26], self.signers[:26])):
            leader_vote = LeaderVote.new(signer, 0, 0, 0, old_leader, next_leader)
            leader_votes.add_vote(leader_vote)

        leader_votes.get_summary()
        print(f"leader_votes.is_completed(): {leader_votes.is_completed()}")
        print(f"leader_votes.get_result(): {leader_votes.get_result()}")
        self.assertEqual(leader_votes.is_completed(), False)
        self.assertEqual(leader_votes.get_result(), None)

        for i, (rep, signer) in enumerate(zip(self.reps[26:55], self.signers[26:55])):
            leader_vote = LeaderVote.new(signer, 0, 0, 0, old_leader, by_higher_rounder)
            leader_votes.add_vote(leader_vote)

        leader_votes.get_summary()
        print(f"leader_votes.is_completed(): {leader_votes.is_completed()}")
        print(f"leader_votes.get_result(): {leader_votes.get_result()}")
        self.assertEqual(leader_votes.is_completed(), True)
        self.assertEqual(leader_votes.get_result(), next_leader)

    def test_leader_invalid_vote(self):
        ratio = 0.67

        old_leader = self.reps[0]
        new_leader = self.reps[1]
        leader_votes = LeaderVotes(self.reps, ratio, 0, 0, old_leader)

        invalid_leader_vote = LeaderVote.new(self.signers[0], 0, 1, 0, old_leader, new_leader)
        self.assertRaises(RuntimeError, leader_votes.add_vote, invalid_leader_vote)

        invalid_leader_vote = LeaderVote.new(self.signers[0], 0, 0, 1, old_leader, new_leader)
        self.assertRaises(RuntimeError, leader_votes.add_vote, invalid_leader_vote)

        invalid_leader_vote = LeaderVote.new(self.signers[0], 0, 0, 0, new_leader, new_leader)
        self.assertRaises(RuntimeError, leader_votes.add_vote, invalid_leader_vote)

        invalid_leader_vote = LeaderVote(rep=self.reps[0], timestamp=0, signature=Signature(os.urandom(65)),
                                         block_height=0, round_=0, new_leader=new_leader, old_leader=old_leader)
        self.assertRaises(RuntimeError, leader_votes.add_vote, invalid_leader_vote)

        leader_vote = LeaderVote.new(self.signers[0], 0, 0, 0, old_leader, new_leader)
        leader_votes.add_vote(leader_vote)
        duplicate_leader_vote = LeaderVote.new(self.signers[0], 0, 0, 0, old_leader, self.reps[2])
        self.assertRaises(votes.VoteDuplicateError, leader_votes.add_vote, duplicate_leader_vote)


if __name__ == '__main__':
    unittest.main()
