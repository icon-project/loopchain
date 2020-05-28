# Copyright 2019 ICON Foundation
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


from loopchain.p2p.protos import loopchain_pb2


class P2PMessage:
    """ Message for protocol buffer

    """

    @staticmethod
    def tx_send(tx=None, tx_json=None, channel=None):
        return loopchain_pb2.TxSend(tx=tx,
                                    tx_json=tx_json,
                                    channel=channel)

    @staticmethod
    def block_send(block=None, round_=None, channel=None):
        return loopchain_pb2.BlockSend(block=block,
                                       round_=round_,
                                       channel=channel)

    @staticmethod
    def block_sync_request(block_height=None, channel=None):
        return loopchain_pb2.BlockSyncRequest(block_height=block_height,
                                              channel=channel)

    @staticmethod
    def status_request(request=None, channel=None):
        return loopchain_pb2.StatusRequest(request=request,
                                           channel=channel)

    @staticmethod
    def complain_leader_request(complain_vote=None, channel=None):
        return loopchain_pb2.ComplainLeaderRequest(complain_vote=complain_vote,
                                                   channel=channel)

    @staticmethod
    def block_vote(vote=None, channel=None):
        return loopchain_pb2.BlockVote(vote=vote,
                                       channel=channel)

    @staticmethod
    def common_request(request=None,
                       channel=None,
                       group_id=None):
        return loopchain_pb2.CommonRequest(request=request,
                                           channel=channel,
                                           group_id=group_id)
