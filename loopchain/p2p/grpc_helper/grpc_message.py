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
    def get_connect_peer_request_message(peer_id=None,
                                         channel=None,
                                         peer_target=None,
                                         group_id=None,
                                         peer_order=None,
                                         peer_object=None):
        return loopchain_pb2.ConnectPeerRequest(peer_id=peer_id,
                                                channel=channel,
                                                peer_target=peer_target,
                                                group_id=group_id,
                                                peer_order=peer_order,
                                                peer_object=peer_object)

    @staticmethod
    def peer_request(peer_id=None,
                     channel=None,
                     peer_target=None,
                     group_id=None,
                     peer_type=None,
                     peer_order=None,
                     peer_object=None,
                     node_type=None):
        return loopchain_pb2.PeerRequest(channel=channel,
                                         peer_target=peer_target,
                                         peer_id=peer_id,
                                         group_id=group_id,
                                         peer_type=peer_type,
                                         peer_order=peer_order,
                                         peer_object=peer_object,
                                         node_type=node_type)

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
    def precommit_block_request(last_block_height=None, channel=None):
        return loopchain_pb2.PrecommitBlockRequest(last_block_height=last_block_height,
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
    def get_peer_id(peer_id=None,
                    channel=None,
                    group_id=None):
        return loopchain_pb2.PeerID(peer_id=peer_id,
                                    channel=channel,
                                    group_id=group_id)

    @staticmethod
    def get_message(code=None,
                    channel=None,
                    message=None,
                    meta=None,
                    object_=None):
        return loopchain_pb2.Message(code=code,
                                     channel=channel,
                                     message=message,
                                     meta=meta,
                                     object=object_)

    @staticmethod
    def common_request(request=None,
                       channel=None,
                       group_id=None):
        return loopchain_pb2.CommonRequest(request=request,
                                           channel=channel,
                                           group_id=group_id)
