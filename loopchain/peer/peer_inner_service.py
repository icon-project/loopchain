"""peer inner service"""

from typing import TYPE_CHECKING

from earlgrey import *

from loopchain import utils as util
from loopchain.utils.message_queue import StubCollection

if TYPE_CHECKING:
    from loopchain.peer import PeerService


class PeerInnerTask:
    def __init__(self, peer_service: 'PeerService'):
        self._peer_service = peer_service

    @message_queue_task
    async def hello(self):
        return 'peer_hello'

    @message_queue_task
    async def get_channel_infos(self):
        return self._peer_service.channel_infos

    @message_queue_task
    async def get_node_info_detail(self):
        return {
            'peer_port': self._peer_service.peer_port,
            'peer_target': self._peer_service.peer_target,
            'rest_target': self._peer_service.rest_target,
            'peer_id': self._peer_service.peer_id
        }

    @message_queue_task
    async def get_node_key(self) -> bytes:
        return self._peer_service.node_key

    @message_queue_task(type_=MessageQueueType.Worker)
    async def stop(self, message):
        logging.info(f"peer_inner_service:stop")
        for stub in StubCollection().channel_stubs.values():
            await stub.async_task().stop(message)

        self._peer_service.close()


class PeerInnerService(MessageQueueService[PeerInnerTask]):
    TaskType = PeerInnerTask

    def _callback_connection_lost_callback(self, connection: RobustConnection):
        util.exit_and_msg("MQ Connection lost.")


class PeerInnerStub(MessageQueueStub[PeerInnerTask]):
    TaskType = PeerInnerTask

    def _callback_connection_lost_callback(self, connection: RobustConnection):
        util.exit_and_msg("MQ Connection lost.")
