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
"""data object for peer votes to a block"""
import logging
import json

from enum import IntEnum

from loopchain.blockchain.hashing import build_hash_generator


class VoteMessageType(IntEnum):
    success = 0
    leader_complain = 1
    leader_ready = 2


class VoteMessage:
    def __init__(self,
                 vote_type: int=VoteMessageType.success,
                 block_height: int=-1,
                 block_hash: str=None,
                 signature=b"",
                 leader_id: str=None,
                 peer_id: str=None,
                 channel_name: str= None):
        """ VoteMessage class to vote block, leader complain and leader ready.

        :param vote_type: A vote type of VoteType attributes.
        :param block_hash: The precommit block hash
        :param block_height: The precommit block height
        :param signature: RecoverableSign to Base64
        :param leader_id: An expected new leader id
        :param peer_id: The Peer ID of this vote.
        """

        self.__type: int = vote_type
        self.__block_hash: str = block_hash
        self.__block_height: int = block_height
        self.__signature: bytes = signature
        self.__leader_id: str = leader_id
        self.__peer_id = peer_id
        self.__channel_name = channel_name
        self.__hash = None
        self.__hash_generator = build_hash_generator(1, None)

    @property
    def type(self):
        return self.__type

    @property
    def block_height(self):
        return self.__block_height

    @property
    def block_hash(self):
        return self.__block_hash

    @property
    def signature(self):
        return self.__signature

    @property
    def leader_id(self):
        return self.__leader_id

    @property
    def peer_id(self):
        return self.__peer_id

    @property
    def channel_name(self):
        return self.__channel_name

    @property
    def vote_hash(self):
        return self.__hash

    def __get_vote_hash(self, json_data: dict, need_sign: bool):
        if not need_sign:
            del json_data["signature"]

        return hash_generator.generate_hash(json_data)

    def print_vote_message(self):
        message = f"VoteMessage:\ntype: {self.__type}\n" \
               f"block_hash: {self.__block_hash}\n" \
               f"block_height: {self.__block_height}\n" \
               f"peer_id: {self.__peer_id}\n" \
               f"signature: {self.__signature}\n" \
               f"hash: {self.__hash}\n"

        if self.__type != VoteMessageType.success:
            message += f"leader_id: {self.__leader_id}"

        return message

    def get_vote_to_json(self):
        json_data = dict()
        json_data["type"] = self.__type
        json_data["block_hash"] = self.__block_hash
        json_data["block_height"] = self.__block_height
        json_data["signature"] = str(self.__signature)
        json_data["peer_id"] = self.__peer_id
        json_data["channel_name"] = self.__channel_name

        if self.__leader_id:
            json_data["leader_id"] = self.__leader_id

        return json_data

    def loads(self, dumps: str):
        try:
            vote = json.loads(dumps)
            if vote is None:
                logging.debug(f"VOTE IS NONE")
                return None
            else:
                self.__type = vote.get("type")
                self.__block_hash = vote.get("block_hash")
                self.__block_height = vote.get("block_height")
                self.__signature = vote.get("signature")
                self.__leader_id = vote.get("leader_id", None)
                self.__peer_id = vote.get("peer_id")
                self.__channel_name = vote.get("channel_name")
                self.__hash = vote.get("hash")
        except KeyError as e:
            logging.error(f"Vote:loads:: The dumps string has no attribute 'vote'. :: {e}")

        return self

    def sign(self, peer_auth):
        vote_hash = self.__get_vote_hash(json_data=self.get_vote_to_json(), need_sign=False)
        self.__signature = peer_auth.sign_data(vote_hash, is_hash=True)

    def get_vote_data(self):
        vote_json_data = self.get_vote_to_json()
        self.__hash = self.__get_vote_hash(json_data=vote_json_data, need_sign=True)

        vote_json_data["hash"] = self.__hash
        result = json.dumps(vote_json_data)

        return result
