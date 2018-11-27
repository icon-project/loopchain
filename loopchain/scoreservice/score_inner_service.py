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

# This file is obsolete.

import pickle

import git
import json
import logging
import random
import threading
import time

from collections import defaultdict
from typing import TYPE_CHECKING, Dict
from earlgrey import message_queue_task, MessageQueueStub, MessageQueueService, MessageQueueType
from loopchain import configure as conf
from loopchain import utils as util
from loopchain.baseservice import PeerScore, ScoreResponse
from loopchain.baseservice.plugin_bases import PluginReturns
from loopchain.blockchain import Block, Transaction, ScoreInvokeError
from loopchain.protos import message_code, loopchain_pb2
from loopchain.tools.score_helper import ScoreHelper

import loopchain_pb2

if TYPE_CHECKING:
    from loopchain.scoreservice import ScoreService


class ScoreInnerTask:
    def __init__(self, score_service: 'ScoreService'):
        self._score_service = score_service

        self.__precommit_usage_lock: threading.Lock = threading.Lock()
        self.__temp_invoke_results = defaultdict(dict)  # type: defaultdict[int, Dict[str, Dict]]

    @message_queue_task
    async def hello(self):
        return 'score_hello'

    @message_queue_task(type_=MessageQueueType.Worker)
    async def stop(self):
        logging.debug("ScoreService handler stop...")
        self._score_service.service_stop()

    @message_queue_task
    async def status(self):
        logging.debug("score_service handler_status")

        status = dict()
        if self._score_service.score:
            status['id'] = self._score_service.score.id()
            status['version'] = self._score_service.score.version()
            status['all_version'] = self._score_service.score.all_version()
            status['status'] = message_code.Response.success
        else:
            status['status'] = message_code.Response.fail
        logging.debug("ScoreService __handler_status : %s", status)

        return status

    @message_queue_task
    async def query(self, params):
        if not util.check_is_json_string(params):
            return message_code.Response.fail_validate_params, ""

        logging.debug(f'Query request with {params}')

        try:
            if self._score_service.score is None:
                logging.error("There is no score!!")
                ret = json.dumps({'code': ScoreResponse.EXCEPTION, 'message': 'There is no score'})
            else:
                try:
                    plugin_result = self._score_service.score_plugin.query(query=params)
                    if plugin_result == PluginReturns.CONTINUE:
                        plugin_result = self._score_service.score.query(params)
                    ret = plugin_result
                except Exception as e:
                    logging.error(f'query {params} raise exception {e}')
                    exception_response = {'code': ScoreResponse.EXCEPTION, 'message': f'Query Raise Exception : {e}'}
                    ret = json.dumps(exception_response)
                    return message_code.Response.success, ret

            response = ret

            peer_id = self._score_service.peer_id
            util.apm_event(peer_id, {
                'event_type': 'Query',
                'peer_id': peer_id,
                'peer_name': conf.PEER_NAME,
                'channel_name': self._score_service.channel_name,
                'data': {'score_query': json.loads(params)}})

        except Exception as e:
            logging.error(f'Execute Query Error : {e}')
            return message_code.Response.fail, ""

        if util.check_is_json_string(response):
            response_code = message_code.Response.success
        else:
            response_code = message_code.Response.fail

        return response_code, response

    @message_queue_task
    async def score_load(self, params):
        logging.debug(f"ScoreService Score Load Request : {params}")

        for i in range(conf.SCORE_GIT_LOAD_RETRY_TIMES):
            try:
                params = json.loads(params)
                self._score_service.peer_id = params[message_code.MetaParams.ScoreLoad.peer_id]

                util.logger.spam(f"score_service:__handler_score_load try init PeerScore")
                self._score_service.score = PeerScore(params[message_code.MetaParams.ScoreLoad.repository_path],
                                                      params[message_code.MetaParams.ScoreLoad.score_package],
                                                      params[message_code.MetaParams.ScoreLoad.base])
                util.logger.spam(f"score_service:__handler_score_load after init PeerScore")

                score_info = dict()
                score_info[message_code.MetaParams.ScoreInfo.score_id] = self._score_service.score.id()
                score_info[message_code.MetaParams.ScoreInfo.score_version] = self._score_service.score.version()
                meta = json.dumps(score_info)
                return loopchain_pb2.Message(code=message_code.Response.success, meta=meta)

            except git.exc.GitCommandError as e:
                logging.exception(f"score_service:__handler_score_load SCORE LOAD IS FAIL params({params}) error({e})")
                logging.info("You may use restarting channel. "
                             "It is because of peers in your machine access git repository at same time.")
                time.sleep(conf.SCORE_GIT_LOAD_SLEEP + random.uniform(-1.0, 1.0))

            except Exception as e:
                logging.exception(f"score_service:__handler_score_load SCORE LOAD IS FAIL params({params}) error({e})")
                return loopchain_pb2.Message(code=message_code.Response.fail, message=str(e))

    @message_queue_task
    def score_invoke(self, block: Block):
        logging.debug("ScoreService handler invoke...")

        invoke_result_list = {}
        code_key = 'code'
        error_message_key = 'message'

        with self.__precommit_usage_lock:
            if not self._score_service.score:
                logging.error("There is no score!!")
                return loopchain_pb2.Message(code=message_code.Response.fail)
            else:
                # get invoke_data if before invoke same block
                saved_results = self.__temp_invoke_results[block.height].get(block.block_hash)
                logging.debug(f"saved invoke result {block.height}, {block.block_hash} : {saved_results}")
                if saved_results:
                    commit_state = ScoreHelper().get_block_commit_state(block.height, block.block_hash)
                    return loopchain_pb2.Message(code=message_code.Response.success,
                                                 meta=json.dumps(saved_results),
                                                 object=pickle.dumps(commit_state))

                logging.debug('tx_list_length : %d ', block.confirmed_tx_len)
                ScoreHelper().init_invoke(block)
                for transaction in block.confirmed_transaction_list:
                    if isinstance(transaction, Transaction) and transaction.tx_hash is not None:
                        tx_hash = transaction.tx_hash
                        invoke_result_list[tx_hash] = {}
                        # put score invoke result to results[tx_hash]
                        invoke_result = {}
                        try:
                            plugin_result = self._score_service.score_plugin.invoke(
                                transaction=transaction,
                                block=block
                            )
                            if plugin_result == PluginReturns.CONTINUE:
                                plugin_result = self._score_service.score.invoke(transaction, block)
                            invoke_result = plugin_result
                            if invoke_result is None:
                                invoke_result_list[tx_hash] = {code_key: message_code.Response.success}
                                ScoreHelper().commit_tx_state()
                            else:
                                if code_key not in invoke_result:
                                    code_not_return = "Score not return code"
                                    if error_message_key in invoke_result:
                                        raise ScoreInvokeError(code_not_return + ": " +
                                                               invoke_result[error_message_key])
                                    raise ScoreInvokeError(code_not_return)
                                elif invoke_result[code_key] == message_code.Response.success:
                                    ScoreHelper().commit_tx_state()
                                elif error_message_key in invoke_result:
                                    invoke_result_list[tx_hash][error_message_key] = invoke_result[error_message_key]
                                    ScoreHelper().reset_tx_state()
                                invoke_result_list[tx_hash][code_key] = invoke_result[code_key]

                        # if score raise exception result to fail and put error message
                        except Exception as e:
                            logging.exception("tx %s score invoke is fail!! : %s ", str(tx_hash), e)
                            ScoreHelper().reset_tx_state()
                            invoke_result[code_key] = ScoreResponse.EXCEPTION
                            invoke_result[error_message_key] = str(e)
                            invoke_result_list[tx_hash] = invoke_result

                        peer_id = transaction.meta[Transaction.PEER_ID_KEY]

                        util.apm_event(self._score_service.peer_id, {
                            'event_type': 'ScoreInvoke',
                            'peer_id': self._score_service.peer_id,
                            'peer_name': conf.PEER_NAME,
                            'channel_name': self._score_service.channel_name,
                            'data': {
                                'request_peer_id': peer_id,
                                'tx_data': transaction.get_data_string(),
                                'invoke_result': invoke_result}})

                try:
                    self._score_service.iiss_plugin.after_invoke(invoke_result_list=invoke_result_list, block=block)
                except Exception as e:
                    logging.error(f"IISS Plugin Exception({e})")
                    util.exit_and_msg(f"Shutdown Peer by IISS Plugin Exception({e})")

                ScoreHelper().precommit_state()

                self.__temp_invoke_results[block.height][block.block_hash] = invoke_result_list

                if block.confirmed_tx_len > 0:
                    commit_state = ScoreHelper().get_block_commit_state(block.height, block.block_hash)
                else:
                    commit_state = {}

                meta = json.dumps(invoke_result_list)
                return loopchain_pb2.Message(
                    code=message_code.Response.success,
                    meta=meta,
                    object=pickle.dumps(commit_state))

    @message_queue_task
    def genesis_invoke(self, block_pickled):
        logging.debug("ScoreService handler genesis invoke...")
        results = {}
        # dict key

        code_key = 'code'
        error_message_key = 'message'

        if not self._score_service.score:
            logging.error("There is no score!!")
            return loopchain_pb2.Message(code=message_code.Response.fail)
        else:
            block = pickle.loads(block_pickled)
            logging.debug('tx_list_length : %d ', block.confirmed_tx_len)
            ScoreHelper().init_invoke(block)
            for transaction in block.confirmed_transaction_list:
                if isinstance(transaction, Transaction) and transaction.tx_hash is not None:
                    tx_hash = transaction.tx_hash
                    results[tx_hash] = {}
                    # put score invoke result to results[tx_hash]
                    try:
                        plugin_result = self._score_service.score_plugin.genesis_invoke(
                            transaction=transaction,
                            block=block
                        )
                        if plugin_result == PluginReturns.CONTINUE:
                            plugin_result = self._score_service.score.genesis_invoke(transaction, block)
                        invoke_result = plugin_result
                        if invoke_result is None:
                            results[tx_hash] = {code_key: message_code.Response.success}
                            ScoreHelper().commit_tx_state()
                        else:
                            if code_key not in invoke_result:
                                code_not_return = "Score not return code"
                                if error_message_key in invoke_result:
                                    raise ScoreInvokeError(code_not_return + ": " + invoke_result[error_message_key])
                                raise ScoreInvokeError(code_not_return)
                            elif invoke_result[code_key] == message_code.Response.success:
                                ScoreHelper().commit_tx_state()
                            elif error_message_key in invoke_result:
                                results[tx_hash][error_message_key] = invoke_result[error_message_key]
                                ScoreHelper().reset_tx_state()
                            results[tx_hash][code_key] = invoke_result[code_key]

                    # if score raise exception result to fail and put error message
                    except Exception as e:
                        logging.exception("tx %s score invoke is fail!! : %s ", str(tx_hash), e)
                        ScoreHelper().reset_tx_state()
                        results[tx_hash][code_key] = ScoreResponse.EXCEPTION
                        results[tx_hash][error_message_key] = str(e)
                        continue

                    util.apm_event(self._score_service.peer_id, {
                        'event_type': 'GenesisInvoke',
                        'peer_id': self._score_service.peer_id,
                        'peer_name': conf.PEER_NAME,
                        'channel_name': self._score_service.channel_name,
                        'data': {
                            'request_peer_id': None,
                            'tx_data': transaction.get_genesis_tx_data(),
                            'invoke_result': invoke_result}})

            logging.debug('results : %s', str(results))
            ScoreHelper().precommit_state()
            meta = json.dumps(results)
            return loopchain_pb2.Message(code=message_code.Response.success, meta=meta)

    @message_queue_task
    def write_precommit_state(self, params):
        with self.__precommit_usage_lock:
            try:
                commit_request = json.loads(params)
                ScoreHelper().commit_block_state(commit_request['block_height'], commit_request['block_hash'])
                self.__remove_temp_invoke_results(commit_request['block_height'])
                return loopchain_pb2.Message(code=message_code.Response.success)
            except Exception as e:
                logging.exception(f"score db commit error : {params}\n"
                                  f"cause : {e}")
                util.exit_and_msg("score db commit fail")
                return loopchain_pb2.Message(code=message_code.Response.fail)

    @message_queue_task
    def remove_precommit_state(self, params):
        with self.__precommit_usage_lock:

            try:
                fail_request = json.loads(params)
                ScoreHelper().reset_precommit_state(fail_request['block_height'], fail_request['block_hash'])
                self.__remove_temp_invoke_results(fail_request['block_height'])
                return loopchain_pb2.Message(code=message_code.Response.success)
            except Exception as e:
                logging.exception(f"score db commit error : {params}\n"
                                  f"cause : {e}")
                util.exit_and_msg("score db proxy reset precommit db fail please restart")
                return loopchain_pb2.Message(code=message_code.Response.fail)

    @message_queue_task
    def change_block_hash(self, params):
        with self.__precommit_usage_lock:
            try:
                change_block_info = json.loads(params)
                ScoreHelper().change_block_hash(block_height=change_block_info['block_height'],
                                                old_block_hash=change_block_info['old_block_hash'],
                                                new_block_hash=change_block_info['new_block_hash'])

                self.__remove_fail_invoke_result_to_new_block_invoke_result(change_block_info)

                return loopchain_pb2.Message(code=message_code.Response.success)
            except Exception as e:
                logging.exception(f"score change block hash fail : {params}\n"
                                  f"cause : {e}")
                # change block_hash fail often because next block commit
                # util.exit_and_msg("score db proxy change block_hash fail please restart")
                return loopchain_pb2.Message(code=message_code.Response.fail)

    def __remove_temp_invoke_results(self, block_height):
        if block_height in self.__temp_invoke_results:
            del self.__temp_invoke_results[block_height]

    def __remove_fail_invoke_result_to_new_block_invoke_result(self, change_block_info):
        block_height = change_block_info['block_height']
        block_hash = change_block_info['old_block_hash']

        saved_results: Dict = self.__temp_invoke_results[block_height].get(block_hash)
        if saved_results:
            fail_result_removed_invoke_results = {tx_hash: invoke_result for tx_hash, invoke_result
                                                  in saved_results.items() if invoke_result['code'] == 0}
            self.__temp_invoke_results[block_height][block_hash] = fail_result_removed_invoke_results


class ScoreInnerService(MessageQueueService[ScoreInnerTask]):
    TaskType = ScoreInnerTask

    def _callback_connection_lost_callback(self, connection):
        util.exit_and_msg("MQ Connection lost.")


class ScoreInnerStub(MessageQueueStub[ScoreInnerTask]):
    TaskType = ScoreInnerTask

    def _callback_connection_lost_callback(self, connection):
        util.exit_and_msg("MQ Connection lost.")
