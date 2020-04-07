"""State Machine for Channel Service"""

import asyncio
import traceback

from earlgrey import MessageQueueService
from transitions import State

import loopchain.utils as util
from loopchain import configure as conf
from loopchain.blockchain import UnrecordedBlock, InvalidUnconfirmedBlock
from loopchain.blockchain.blocks import Block
from loopchain.blockchain.exception import ConsensusChanged
from loopchain.peer import status_code
from loopchain.protos import loopchain_pb2
from loopchain.statemachine import statemachine
from loopchain.utils import loggers


@statemachine.StateMachine("Channel State Machine")
class ChannelStateMachine(object):
    states = ['InitComponents',
              State(name='Consensus',
                    ignore_invalid_triggers=True,
                    on_enter='_consensus_on_enter'),
              State(name='BlockHeightSync',
                    ignore_invalid_triggers=True,
                    on_enter='_blockheightsync_on_enter'),
              'EvaluateNetwork',
              State(name='BlockSync',
                    ignore_invalid_triggers=True,
                    on_enter='_blocksync_on_enter',
                    on_exit='_blocksync_on_exit'),
              State(name='SubscribeNetwork',
                    ignore_invalid_triggers=True,
                    on_enter='_subscribe_network_on_enter',
                    on_exit='_subscribe_network_on_exit'),
              State(name='Watch',
                    ignore_invalid_triggers=True,
                    on_enter='_watch_on_enter', 
                    on_exit='_watch_on_exit'),
              State(name='Vote',
                    ignore_invalid_triggers=True,
                    on_enter='_vote_on_enter',
                    on_exit='_vote_on_exit'),
              State(name='BlockGenerate',
                    ignore_invalid_triggers=True,
                    on_enter='_blockgenerate_on_enter',
                    on_exit='_blockgenerate_on_exit'),
              State(name='LeaderComplain',
                    ignore_invalid_triggers=True,
                    on_enter='_leadercomplain_on_enter',
                    on_exit='_leadercomplain_on_exit'),
              State(name='ResetNetwork',
                    ignore_invalid_triggers=True,
                    on_enter='_do_reset_network_on_enter'),
              'GracefulShutdown']
    init_state = 'InitComponents'
    state = init_state
    service_available_states = ["BlockGenerate", "Vote", "LeaderComplain", "Watch"]

    def __init__(self, channel_service):
        self.__channel_service = channel_service

        self.machine.add_transition(
            'complete_subscribe', 'SubscribeNetwork', 'BlockGenerate', conditions=['_is_leader'])
        self.machine.add_transition(
            'complete_subscribe', 'SubscribeNetwork', 'Watch', conditions=['_has_no_vote_function'])
        self.machine.add_transition('complete_subscribe', 'SubscribeNetwork', 'Vote')

    @statemachine.transition(source='InitComponents', dest='Consensus')
    def complete_init_components(self):
        pass

    @statemachine.transition(source='Consensus', dest='BlockHeightSync')
    def block_height_sync(self):
        pass

    @statemachine.transition(source=('BlockHeightSync', 'ResetNetwork'),
                             dest='EvaluateNetwork',
                             after='_do_evaluate_network')
    def evaluate_network(self):
        pass

    @statemachine.transition(source=('EvaluateNetwork', 'SubscribeNetwork', 'Watch',
                                     'Vote', 'BlockSync', 'BlockGenerate', 'LeaderComplain'),
                             dest='BlockSync',
                             after='_do_block_sync')
    def block_sync(self):
        pass

    @statemachine.transition(source=('Watch', 'SubscribeNetwork'), dest='SubscribeNetwork')
    def subscribe_network(self):
        pass

    @statemachine.transition(source=('Vote', 'LeaderComplain'), dest='Vote', after='_do_vote')
    def vote(self):
        pass

    def complete_subscribe(self):
        pass

    @statemachine.transition(source='BlockSync', dest='SubscribeNetwork')
    def complete_sync(self):
        pass

    @statemachine.transition(source=('BlockGenerate', 'Vote', 'LeaderComplain'), dest='Vote')
    def turn_to_peer(self):
        pass

    @statemachine.transition(source=('Vote', 'BlockGenerate', 'LeaderComplain'), dest='BlockGenerate')
    def turn_to_leader(self):
        pass

    @statemachine.transition(source=('Vote', 'LeaderComplain'), dest='LeaderComplain')
    def leader_complain(self):
        pass

    @statemachine.transition(source=('BlockSync', 'BlockGenerate', 'Vote', 'Watch'), dest='ResetNetwork')
    def switch_role(self):
        pass

    def _is_leader(self):
        return (not self._has_no_vote_function() and
                self.__channel_service.block_manager.peer_type == loopchain_pb2.BLOCK_GENERATOR)

    def _has_no_vote_function(self):
        return not self.__channel_service.is_support_node_function(conf.NodeFunction.Vote)

    def _do_block_sync(self):
        self.__channel_service.block_manager.block_height_sync()

    def _do_evaluate_network(self):
        self._run_coroutine_threadsafe(self.__channel_service.evaluate_network())

    def _do_vote(self, unconfirmed_block: Block, round_: int):
        if unconfirmed_block.header.is_unrecorded:
            try:
                self._run_coroutine_threadsafe(
                    self.__channel_service.block_manager.add_unconfirmed_block(unconfirmed_block, round_))
            except UnrecordedBlock as e:
                util.logger.info(e)
            except InvalidUnconfirmedBlock as e:
                util.logger.spam(f"The Unrecorded block is unnecessary to vote.")
        else:
            self._run_coroutine_threadsafe(
                self.__channel_service.block_manager.vote_as_peer(unconfirmed_block, round_))

    def _consensus_on_enter(self, *args, **kwargs):
        self.block_height_sync()

    def _blockheightsync_on_enter(self, *args, **kwargs):
        self.evaluate_network()

    def _blocksync_on_enter(self, *args, **kwargs):
        self.__channel_service.block_manager.update_service_status(status_code.Service.block_height_sync)

    def _blocksync_on_exit(self, *args, **kwargs):
        self.__channel_service.update_nid()

        self.__channel_service.block_manager.blockchain.reset_leader_made_block_count(need_check_switched_role=True)
        self.__channel_service.block_manager.stop_block_height_sync_timer()
        self.__channel_service.block_manager.update_service_status(status_code.Service.online)

    def _subscribe_network_on_enter(self, *args, **kwargs):
        self.__channel_service.start_subscribe_timer()
        self.__channel_service.start_shutdown_timer_when_fail_subscribe()

        self._run_coroutine_threadsafe(self.__channel_service.subscribe_network())

    def _subscribe_network_on_exit(self, *args, **kwargs):
        self.__channel_service.stop_subscribe_timer()
        self.__channel_service.stop_shutdown_timer_when_fail_subscribe()

    def _watch_on_enter(self, *args, **kwargs):
        loggers.get_preset().is_leader = False
        loggers.get_preset().update_logger()
        self._run_coroutine_threadsafe(self.__channel_service.block_manager.relay_all_txs())
        self.__channel_service.start_block_monitoring_timer()

    def _watch_on_exit(self, *args, **kwargs):
        self.__channel_service.stop_ws_heartbeat_timer()
        self.__channel_service.stop_block_monitoring_timer()
        self._run_coroutine_threadsafe(self.__channel_service.node_subscriber.close())

    def _do_reset_network_on_enter(self):
        self._run_coroutine_threadsafe(self.__channel_service.reset_network())

    def _vote_on_enter(self, *args, **kwargs):
        loggers.get_preset().is_leader = False
        loggers.get_preset().update_logger()

    def _vote_on_exit(self, *args, **kwargs):
        pass

    def _blockgenerate_on_enter(self, *args, **kwargs):
        loggers.get_preset().is_leader = True
        loggers.get_preset().update_logger()
        if conf.SAFE_BLOCK_BROADCAST:
            self.__channel_service.inner_service.notify_unregister()
        self.__channel_service.block_manager.start_block_generate_timer()

    def _blockgenerate_on_exit(self, *args, **kwargs):
        self.__channel_service.block_manager.stop_block_generate_timer()

    def _leadercomplain_on_enter(self, *args, **kwargs):
        util.logger.debug(f"_leadercomplain_on_enter")
        self.__channel_service.block_manager.leader_complain()

    def _leadercomplain_on_exit(self, *args, **kwargs):
        util.logger.debug(f"_leadercomplain_on_exit")

    def _run_coroutine_threadsafe(self, coro):
        async def _run_with_handling_exception():
            try:
                await coro
            except ConsensusChanged as e:
                loop.exception = e
                loop.stop()
            except Exception:
                traceback.print_exc()

        loop = MessageQueueService.loop
        asyncio.run_coroutine_threadsafe(_run_with_handling_exception(), loop)
