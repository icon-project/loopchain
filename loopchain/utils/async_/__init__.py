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

import asyncio
import threading
from concurrent import futures


def thread_monkey_patch():
    threading.Thread.__await__ = __thread__await__


def __thread__await__(self: threading.Thread):
    while self.is_alive():
        yield from asyncio.sleep(0.5)


def concurrent_future_monkey_patch():
    futures.Future.__await__ = __concurrent_future__await__


def __concurrent_future__await__(self: futures.Future):
    def _callback():
        try:
            future.set_result(self.result())
        except BaseException as e:
            future.set_exception(e)

    loop: asyncio.BaseEventLoop = asyncio.get_event_loop()
    self.add_done_callback(lambda _: loop.call_soon_threadsafe(_callback))

    future = asyncio.Future()
    yield from future

    return future.result()

