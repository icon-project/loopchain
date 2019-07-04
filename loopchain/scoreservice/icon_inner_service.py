# Copyright 2017-2018 theloop Inc.
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

from earlgrey import message_queue_task, MessageQueueStub

from loopchain import utils


class IconScoreInnerTask:

    @message_queue_task
    async def hello(self):
        pass

    @message_queue_task
    async def close(self):
        pass

    @message_queue_task
    async def invoke(self, request: dict) -> dict:
        pass

    @message_queue_task
    async def query(self, request: dict) -> dict:
        pass

    @message_queue_task
    async def call(self, request: dict) -> dict:
        pass

    @message_queue_task
    async def write_precommit_state(self, request: dict) -> dict:
        pass

    @message_queue_task
    async def remove_precommit_state(self, request: dict) -> dict:
        pass

    @message_queue_task
    async def validate_transaction(self, request: dict) -> dict:
        pass

    @message_queue_task
    async def change_block_hash(self, params) -> dict:
        pass


class IconScoreInnerStub(MessageQueueStub[IconScoreInnerTask]):
    TaskType = IconScoreInnerTask

    def _callback_connection_lost_callback(self, connection):
        utils.exit_and_msg("MQ Connection lost.")
