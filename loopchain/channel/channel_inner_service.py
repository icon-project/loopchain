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

import ast
import copy
import json
import pickle
import re
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING
from earlgrey import *

from loopchain import configure as conf
from loopchain import utils as util
from loopchain.baseservice import BroadcastCommand, TimerService, ScoreResponse
from loopchain.blockchain import Transaction, get_tx_validator, Block, BlockType
from loopchain.blockchain.exception import *
from loopchain.channel.channel_property import ChannelProperty
from loopchain.consensus import Epoch, VoteMessage
from loopchain.protos import loopchain_pb2, message_code

if TYPE_CHECKING:
    from loopchain.channel.channel_service import ChannelService


class ChannelInnerTask:
    def __init__(self, channel_service: 'ChannelService'):
        self._channel_service = channel_service
        self._thread_pool = ThreadPoolExecutor(1, "ChannelInnerThread")

    @message_queue_task
    async def hello(self):
        return 'channel_hello'

    @message_queue_task
    def get_peer_list(self):
        peer_manager = self._channel_service.peer_manager
        return str(peer_manager.peer_list[conf.ALL_GROUP_ID]), str(peer_manager.peer_list)

    @message_queue_task(type_=MessageQueueType.Worker)
    async def reset_leader(self, new_leader, block_height=0) -> None:
        await self._channel_service.reset_leader(new_leader, block_height)

    @message_queue_task(priority=255)
    async def get_status(self):
        block_height = 0
        total_tx = 0

        status_data = dict()

        block_manager = self._channel_service.block_manager
        status_data["made_block_count"] = block_manager.get_blockchain().made_block_count
        if block_manager.get_blockchain().last_block is not None:
            block_height = block_manager.get_blockchain().last_block.height
            logging.debug("getstatus block hash(block_manager.get_blockchain().last_block.block_hash): "
                          + str(block_manager.get_blockchain().last_block.block_hash))
            logging.debug("getstatus block hash(block_manager.get_blockchain().block_height): "
                          + str(block_manager.get_blockchain().block_height))
            logging.debug("getstatus block height: " + str(block_height))
            # Score와 상관없이 TransactionTx는 블럭매니저가 관리 합니다.
            total_tx = block_manager.get_total_tx()

        status_data["status"] = block_manager.service_status
        status_data["state"] = self._channel_service.state_machine.state
        status_data["peer_type"] = str(block_manager.peer_type)
        status_data["audience_count"] = "0"
        status_data["consensus"] = str(conf.CONSENSUS_ALGORITHM.name)
        status_data["peer_id"] = str(ChannelProperty().peer_id)
        status_data["block_height"] = block_height
        status_data["total_tx"] = total_tx
        status_data["unconfirmed_tx"] = block_manager.get_count_of_unconfirmed_tx()
        status_data["peer_target"] = ChannelProperty().peer_target
        status_data["leader_complaint"] = 1

        return status_data

    @message_queue_task
    def create_tx(self, data):
        tx = Transaction()
        score_id = ""
        score_version = ""

        try:
            score_info = self._channel_service.score_info
            score_id = score_info[message_code.MetaParams.ScoreInfo.score_id]
            score_version = score_info[message_code.MetaParams.ScoreInfo.score_version]
        except KeyError as e:
            logging.debug(f"CreateTX : load score info fail\n"
                          f"cause : {e}")

        send_tx_type = self._channel_service.get_channel_option()["send_tx_type"]
        tx.init_meta(ChannelProperty().peer_id, score_id, score_version, ChannelProperty().name, send_tx_type)
        tx.put_data(data)
        tx.sign_hash(self._channel_service.peer_auth)

        self._channel_service.broadcast_scheduler.schedule_job(BroadcastCommand.CREATE_TX, tx)

        try:
            data_log = json.loads(data)
        except Exception as e:
            data_log = {'tx_hash': tx.tx_hash}

        util.apm_event(ChannelProperty().peer_id, {
            'event_type': 'CreateTx',
            'peer_id': ChannelProperty().peer_id,
            'peer_name': conf.PEER_NAME,
            'channel_name': ChannelProperty().name,
            'tx_hash': tx.tx_hash,
            'data': data_log})

        return tx.tx_hash

    @message_queue_task
    async def create_icx_tx(self, kwargs: dict):
        tx_validator = get_tx_validator(ChannelProperty().name)

        result_code = None
        exception = None

        tx = None
        try:
            tx = tx_validator.validate_dumped_tx_message(json.dumps(kwargs))

            block_manager = self._channel_service.block_manager
            block_manager.pre_validate(tx)

        except TransactionInvalidError as e:
            result_code = e.message_code
            exception = e
        except BaseException as e:
            result_code = TransactionInvalidError.message_code
            exception = e
        finally:
            if exception:
                logging.warning(f"create_icx_tx: tx restore fail for kwargs({kwargs}), {exception}")
                return result_code, None

        logging.debug(f"create icx input : {tx.icx_origin_data}")

        self._channel_service.broadcast_scheduler.schedule_job(BroadcastCommand.CREATE_TX, tx)
        return message_code.Response.success, tx.tx_hash

    @message_queue_task(type_=MessageQueueType.Worker)
    def add_tx(self, request) -> None:
        tx_validator = get_tx_validator(ChannelProperty().name)
        tx_dumped = tx_validator.load_dumped_tx(request)
        tx = tx_validator.validate_dumped_tx_message(tx_dumped)
        # util.logger.spam(f"channel_inner_service:add_tx tx({tx.get_data_string()})")

        object_has_queue = self._channel_service.get_object_has_queue_by_consensus()
        if tx is not None:
            object_has_queue.add_tx_obj(tx)
            util.apm_event(ChannelProperty().peer_id, {
                'event_type': 'AddTx',
                'peer_id': ChannelProperty().peer_id,
                'peer_name': conf.PEER_NAME,
                'channel_name': ChannelProperty().name,
                'data': {'tx_hash': tx.tx_hash}})

    @message_queue_task(type_=MessageQueueType.Worker)
    def add_tx_list(self, request) -> tuple:
        tx_validate_count = 0
        tx_validator = get_tx_validator(ChannelProperty().name)

        for tx_item in request.tx_list:
            tx_dumped = tx_validator.load_dumped_tx(tx_item)
            tx = tx_validator.validate_dumped_tx_message(tx_dumped)
            # util.logger.spam(f"channel_inner_service:add_tx tx({tx.get_data_string()})")

            object_has_queue = self._channel_service.get_object_has_queue_by_consensus()
            if tx is not None:
                object_has_queue.add_tx_obj(tx)
                tx_validate_count += 1
                util.apm_event(ChannelProperty().peer_id, {
                    'event_type': 'AddTx',
                    'peer_id': ChannelProperty().peer_id,
                    'peer_name': conf.PEER_NAME,
                    'channel_name': ChannelProperty().name,
                    'data': {'tx_hash': tx.tx_hash}})

        if tx_validate_count == 0:
            response_code = message_code.Response.fail
            message = "fail tx validate while AddTxList"
        else:
            response_code = message_code.Response.success
            message = f"success ({tx_validate_count})/({len(request.tx_list)})"

        return response_code, message

    @message_queue_task
    def get_tx(self, tx_hash):
        return self._channel_service.block_manager.get_tx(tx_hash)

    @message_queue_task
    def get_tx_info(self, tx_hash):
        tx = self._channel_service.block_manager.get_tx_queue().get(tx_hash, None)
        if tx:
            logging.info(f"get_tx_info pending : tx_hash({tx_hash})")
            tx_info = dict()
            tx_info["transaction"] = tx.icx_origin_data_v3
            tx_info["tx_index"] = None
            tx_info["block_height"] = None
            tx_info["block_hash"] = None
            return message_code.Response.success, tx_info
        else:
            try:
                return message_code.Response.success, self._channel_service.block_manager.get_tx_info(tx_hash)
            except KeyError as e:
                logging.error(f"get_tx_info error : tx_hash({tx_hash}) not found error({e})")
                response_code = message_code.Response.fail_invalid_key_error
                return response_code, None

    @message_queue_task(type_=MessageQueueType.Worker)
    async def announce_unconfirmed_block(self, block_pickled) -> None:
        unconfirmed_block = util.block_loads(block_pickled)

        logging.debug(f"#block \n"
                      f"peer_id({unconfirmed_block.peer_id})\n"
                      f"height({unconfirmed_block.height})\n"
                      f"hash({unconfirmed_block.block_hash})\n"
                      f"made_block_count({unconfirmed_block.made_block_count})\n"
                      f"block_type({unconfirmed_block.block_type})\n"
                      f"is_divided_block({unconfirmed_block.is_divided_block})\n")

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            self._thread_pool,
            self._channel_service.block_manager.add_unconfirmed_block,
            unconfirmed_block)

        self._channel_service.state_machine.vote()

        if unconfirmed_block.made_block_count >= conf.LEADER_BLOCK_CREATION_LIMIT \
                and unconfirmed_block.block_type is BlockType.vote \
                and unconfirmed_block.is_divided_block is False:
            util.logger.spam(f"channel_inner_service:AnnounceUnconfirmedBlock try self.peer_service.reset_leader"
                             f"\nnext_leader_peer({unconfirmed_block.next_leader_peer}, "
                             f"channel({ChannelProperty().name}))")

            # (hotfix-81) 자기가 다음 리더 일때만 AnnounceUnconfirmedBlock 메시지에서 reset leader 를 호출한다.
            if ChannelProperty().peer_id == unconfirmed_block.next_leader_peer:
                await self._channel_service.reset_leader(unconfirmed_block.next_leader_peer)

    @message_queue_task
    async def announce_confirmed_block(self, serialized_block, commit_state="{}"):
        try:
            confirmed_block = Block(channel_name=ChannelProperty().name)
            confirmed_block.deserialize_block(serialized_block)
            util.logger.spam(f"channel_inner_service:announce_confirmed_block\n "
                             f"hash({confirmed_block.block_hash}), block_type({confirmed_block.block_type}), "
                             f"block height({confirmed_block.height}), "
                             f"commit_state({commit_state})")
            try:
                confirmed_block.commit_state = ast.literal_eval(commit_state)
            except Exception as e:
                logging.warning(f"channel_inner_service:announce_confirmed_block FAIL get commit_state_dict, "
                                f"error by : {e}")

            if self._channel_service.block_manager.get_blockchain().block_height < confirmed_block.height:
                self._channel_service.block_manager.add_confirmed_block(confirmed_block)
            else:
                logging.debug(f"channel_inner_service:announce_confirmed_block "
                              f"already synced block height({confirmed_block.height})")
            response_code = message_code.Response.success
            # stop subscribe timer
            if TimerService.TIMER_KEY_SUBSCRIBE in self._channel_service.timer_service.timer_list.keys():
                self._channel_service.timer_service.stop_timer(TimerService.TIMER_KEY_SUBSCRIBE)
        except Exception as e:
            logging.error(f"announce confirmed block error : {e}")
            response_code = message_code.Response.fail
        return response_code

    @message_queue_task
    def announce_new_block_for_vote(self, block: Block, epoch: Epoch):
        acceptor = self._channel_service.acceptor
        if acceptor.epoch is None:
            pass
        else:
            acceptor.epoch.block_hash = block.block_hash
            acceptor.create_vote(block=block, epoch=epoch)

    @message_queue_task
    def block_sync(self, block_hash, block_height):
        block_manager = self._channel_service.block_manager

        response_message = None
        block: Block = None
        if block_hash != "":
            block = block_manager.get_blockchain().find_block_by_hash(block_hash)
        elif block_height != -1:
            block = block_manager.get_blockchain().find_block_by_height(block_height)
        else:
            response_message = message_code.Response.fail_not_enough_data

        if block is None:
            if response_message is None:
                response_message = message_code.Response.fail_wrong_block_hash

            return response_message, -1, block_manager.get_blockchain().block_height, None

        # add commit_state if block is last of this peer
        if block.height == block_manager.get_blockchain().last_commit_state_height:
            block.commit_state = copy.deepcopy(block_manager.get_blockchain().last_commit_state)

        block_dumped = util.block_dumps(block)
        return message_code.Response.success, block.height, block_manager.get_blockchain().block_height, block_dumped

    @message_queue_task(type_=MessageQueueType.Worker)
    def block_height_sync(self, target_peer_stub=None):
        self._channel_service.block_manager.block_height_sync(target_peer_stub)

    @message_queue_task(type_=MessageQueueType.Worker)
    def add_audience(self, peer_target) -> None:
        self._channel_service.broadcast_scheduler.schedule_job(BroadcastCommand.SUBSCRIBE, peer_target)

    @message_queue_task(type_=MessageQueueType.Worker)
    def remove_audience(self, peer_target) -> None:
        self._channel_service.broadcast_scheduler.schedule_job(BroadcastCommand.UNSUBSCRIBE, peer_target)

    @message_queue_task
    async def add_audience_subscriber(self, peer_target):
        if peer_target not in self._channel_service.broadcast_scheduler.audience_subscriber:
            if len(self._channel_service.broadcast_scheduler.audience_subscriber) < conf.SUBSCRIBE_LIMIT:
                logging.debug(f"channel_inner_service:add_audience_subscriber target({peer_target})")
                self._channel_service.broadcast_scheduler.schedule_job(BroadcastCommand.AUDIENCE_SUBSCRIBE, peer_target)
                response_code = message_code.Response.success
            else:
                logging.warning(f"This peer can no longer take more subscribe requests!")
                response_code = message_code.Response.fail
        else:
            logging.info(f"This target({peer_target}) is already subscribing this peer")
            util.logger.spam(f"audience_subscriber list : "
                             f"{self._channel_service.broadcast_scheduler.audience_subscriber.keys()}")
            response_code = message_code.Response.success
        return response_code

    @message_queue_task
    async def remove_audience_subscriber(self, peer_target):
        if peer_target in self._channel_service.broadcast_scheduler.audience_subscriber:
            self._channel_service.broadcast_scheduler.schedule_job(BroadcastCommand.AUDIENCE_UNSUBSCRIBE, peer_target)
            response_code = message_code.Response.success
        else:
            logging.warning(f"This target({peer_target}) already unsubscribed this peer")
            response_code = message_code.Response.success
        return response_code

    @message_queue_task(type_=MessageQueueType.Worker)
    def announce_new_peer(self, peer_object_pickled, peer_target) -> None:
        peer_object = pickle.loads(peer_object_pickled)
        logging.debug("Add New Peer: " + str(peer_object.peer_id))

        peer_manager = self._channel_service.peer_manager
        peer_manager.add_peer(peer_object)
        # broadcast the new peer to the others for adding an audience
        self._channel_service.broadcast_scheduler.schedule_job(BroadcastCommand.SUBSCRIBE, peer_target)

        logging.debug("Try save peer list...")
        self._channel_service.save_peer_manager(peer_manager)
        self._channel_service.show_peers()

        if conf.CONSENSUS_ALGORITHM == conf.ConsensusAlgorithm.lft:
            quorum, complain_quorum = peer_manager.get_quorum()
            self._channel_service.consensus.set_quorum(quorum=quorum, complain_quorum=complain_quorum)

    @message_queue_task(type_=MessageQueueType.Worker)
    def delete_peer(self, peer_id, group_id) -> None:
        self._channel_service.peer_manager.remove_peer(peer_id, group_id)

    @message_queue_task(type_=MessageQueueType.Worker)
    def vote_unconfirmed_block(self, peer_id, group_id, block_hash, vote_code) -> None:
        block_manager = self._channel_service.block_manager
        util.logger.spam(f"channel_inner_service:VoteUnconfirmedBlock ({ChannelProperty().name})")
        peer_type = loopchain_pb2.PEER
        if block_manager is not None:
            peer_type = block_manager.peer_type

        if conf.CONSENSUS_ALGORITHM != conf.ConsensusAlgorithm.lft:
            if peer_type == loopchain_pb2.PEER:
                # util.logger.warning(f"peer_outer_service:VoteUnconfirmedBlock ({channel_name}) Not Leader Peer!")
                return

        logging.info("Peer vote to : " + block_hash + " " + str(vote_code) + f"from {peer_id}")

        block_manager.get_candidate_blocks().vote_to_block(
            block_hash, (False, True)[vote_code == message_code.Response.success_validate_block],
            peer_id, group_id)

    @message_queue_task
    async def broadcast_vote(self, vote: VoteMessage):
        acceptor = self._channel_service.acceptor
        if acceptor.epoch is None:
            pass
        else:
            await acceptor.apply_vote_into_block(vote)

    @message_queue_task
    def get_invoke_result(self, tx_hash):
        try:
            invoke_result = self._channel_service.block_manager.get_invoke_result(tx_hash)
            invoke_result_str = json.dumps(invoke_result)
            response_code = message_code.Response.success
            logging.debug('invoke_result : ' + invoke_result_str)

            util.apm_event(ChannelProperty().peer_id, {
                'event_type': 'GetInvokeResult',
                'peer_id': ChannelProperty().peer_id,
                'peer_name': conf.PEER_NAME,
                'channel_name': ChannelProperty().name,
                'data': {'invoke_result': invoke_result, 'tx_hash': tx_hash}})

            if 'code' in invoke_result:
                if invoke_result['code'] == ScoreResponse.NOT_EXIST:
                    logging.debug(f"get invoke result NOT_EXIST tx_hash({tx_hash})")
                    response_code = message_code.Response.fail_invalid_key_error
                elif invoke_result['code'] == ScoreResponse.NOT_INVOKED:
                    logging.info(f"get invoke result NOT_INVOKED tx_hash({tx_hash})")
                    response_code = message_code.Response.fail_tx_not_invoked

            return response_code, invoke_result_str
        except BaseException as e:
            logging.error(f"get invoke result error : {e}")
            util.apm_event(ChannelProperty().peer_id, {
                'event_type': 'Error',
                'peer_id': ChannelProperty().peer_id,
                'peer_name': conf.PEER_NAME,
                'channel_name': ChannelProperty().name,
                'data': {
                    'error_type': 'InvokeResultError',
                    'code': message_code.Response.fail,
                    'message': f"get invoke result error : {e}"}})
            return message_code.Response.fail, None

    @message_queue_task
    async def get_block_v2(self, block_height, block_hash, block_data_filter, tx_data_filter):
        # This is a temporary function for v2 support of exchanges.
        block, block_filter, block_hash, fail_response_code, tx_filter = await self.__get_block(
            block_data_filter, block_hash, block_height, tx_data_filter)
        if fail_response_code:
            return fail_response_code, block_hash, json.dumps({}), ""

        block_data_dict = json.loads(block.serialize_block().decode())

        if block.height == 0:
            return message_code.Response.success, block.block_hash, json.dumps(block_data_dict), []

        confirmed_tx_list = block_data_dict["confirmed_transaction_list"]
        confirmed_tx_list_without_fail = []

        for tx in confirmed_tx_list:
            tx_hash = util.get_tx_hash(tx)
            invoke_result = self._channel_service.block_manager.get_invoke_result(tx_hash)

            if 'failure' in invoke_result:
                continue

            if util.get_tx_version(tx) == conf.ApiVersion.v3:
                step_used, step_price = int(invoke_result["stepUsed"], 16), int(invoke_result["stepPrice"], 16)
                tx["fee"] = hex(step_used * step_price)

            confirmed_tx_list_without_fail.append(tx)

        # Replace the existing confirmed_tx_list with v2 ver.
        block_data_dict["confirmed_transaction_list"] = confirmed_tx_list_without_fail
        block_data_json = json.dumps(block_data_dict)

        if fail_response_code:
            return fail_response_code, block_hash, json.dumps({}), []

        return message_code.Response.success, block.block_hash, block_data_json, []

    @message_queue_task
    async def get_block(self, block_height, block_hash, block_data_filter, tx_data_filter):
        block, block_filter, block_hash, fail_response_code, tx_filter = await self.__get_block(
            block_data_filter, block_hash, block_height, tx_data_filter)

        if fail_response_code:
            return fail_response_code, block_hash, json.dumps({}), ""

        if self._channel_service.get_channel_option()["send_tx_type"] == conf.SendTxType.icx:
            return message_code.Response.success, block.block_hash, block.serialize_block().decode(), []
        else:
            block_data = dict()
            for key in block_filter:
                try:
                    block_data[key] = str(getattr(block, key))
                except AttributeError:
                    try:
                        getter = getattr(block, "get_" + key)
                        block_data[key] = getter()
                    except AttributeError:
                        block_data[key] = ""

            tx_data_json_list = []
            for tx in block.confirmed_transaction_list:
                tx_data_json = json.loads("{}")
                for key in tx_filter:
                    try:
                        tx_data_json[key] = str(getattr(tx, key))
                    except AttributeError:
                        try:
                            getter = getattr(tx, "get_" + key)
                            tx_data_json[key] = getter()
                        except AttributeError:
                            tx_data_json[key] = ""
                tx_data_json_list.append(json.dumps(tx_data_json))

            block_data_json = json.dumps(block_data)

        return message_code.Response.success, block.block_hash, block_data_json, tx_data_json_list

    async def __get_block(self, block_data_filter, block_hash, block_height, tx_data_filter):
        block_manager = self._channel_service.block_manager
        if block_hash == "" and block_height == -1:
            block_hash = block_manager.get_blockchain().last_block.block_hash
        block_filter = re.sub(r'\s', '', block_data_filter).split(",")
        tx_filter = re.sub(r'\s', '', tx_data_filter).split(",")

        block = None
        fail_response_code = None
        if block_hash:
            block = block_manager.get_blockchain().find_block_by_hash(block_hash)
            if block is None:
                fail_response_code = message_code.Response.fail_wrong_block_hash
        elif block_height != -1:
            block = block_manager.get_blockchain().find_block_by_height(block_height)
            if block is None:
                fail_response_code = message_code.Response.fail_wrong_block_height
        else:
            fail_response_code = message_code.Response.fail_wrong_block_hash

        return block, block_filter, block_hash, fail_response_code, tx_filter

    @message_queue_task
    def get_precommit_block(self, last_block_height: int):
        block_manager = self._channel_service.block_manager
        precommit_block = block_manager.get_blockchain().get_precommit_block()

        if precommit_block is None:
            return message_code.Response.fail, "there is no precommit block.", b""
        if precommit_block.height != last_block_height + 1:
            return message_code.Response.fail, "need block height sync.", b""

        return message_code.Response.success, "success", pickle.dumps(precommit_block)

    @message_queue_task
    def get_tx_by_address(self, address, index):
        block_manager = self._channel_service.block_manager
        tx_list, next_index = block_manager.get_blockchain().get_tx_list_by_address(address=address, index=index)

        return tx_list, next_index

    @message_queue_task
    def get_score_status(self):
        score_status = ""
        try:
            score_status_response = self._channel_service.score_stub.call(
                "Request",
                loopchain_pb2.Message(code=message_code.Request.status)
            )

            logging.debug("Get Score Status : " + str(score_status_response))

        except Exception as e:
            logging.debug("Score Service Already stop by other reason. %s", e)

        else:
            if score_status_response.code == message_code.Response.success:
                score_status = score_status_response.meta

        return score_status

    @message_queue_task
    def reset_timer(self, key):
        self._channel_service.timer_service.reset_timer(key)

    @message_queue_task(type_=MessageQueueType.Worker)
    def stop(self, message):
        logging.info(f"channel_inner_service:stop message({message})")
        self._channel_service.close()


class ChannelInnerService(MessageQueueService[ChannelInnerTask]):
    TaskType = ChannelInnerTask

    def _callback_connection_lost_callback(self, connection: RobustConnection):
        util.exit_and_msg("MQ Connection lost.")


class ChannelInnerStub(MessageQueueStub[ChannelInnerTask]):
    TaskType = ChannelInnerTask

    def _callback_connection_lost_callback(self, connection: RobustConnection):
        util.exit_and_msg("MQ Connection lost.")
