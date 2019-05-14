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
"""A class to handle block sync data"""

import abc
import traceback

from loopchain import configure
from loopchain import utils
from loopchain.blockchain import Block
from loopchain.protos import message_code


class BlockSynchronizer(abc.ABC):
    def __init__(self, peer_stubs, my_height: int):
        self._peer_stubs = peer_stubs
        self._peer_index = -1
        self._touched_every_stub = False
        self._retry_number = 0
        self._unconfirmed_block = None
        self._unconfirmed_height = -1
        self._last_height = -1
        self._max_height = -1
        self._my_height = my_height

    def __iter__(self):
        return self

    def __next__(self):
        if len(self._peer_stubs) == 0 or (self._touched_every_stub and self._my_height >= self._max_height):
            raise StopIteration

        self._peer_index = (self._peer_index + 1) % len(self._peer_stubs)
        self._touched_peer_stub()
        return self._peer_stubs[self._peer_index], self._my_height + 1

    def _erase(self):
        """Erase current peer_stub
        """
        del self._peer_stubs[self._peer_index]
        self._peer_index -= 1

    @abc.abstractmethod
    def _block_request(self, peer_stub):
        raise NotImplementedError("_block_request function is interface method")

    @property
    def max_height(self):
        return self._max_height

    @property
    def unconfirmed_block(self):
        return self._unconfirmed_block

    def _touched_peer_stub(self):
        if not self._touched_every_stub and self._peer_index == len(self._peer_stubs) - 1:
            utils.logger.debug("Completed to get height info.")
            self._touched_every_stub = True

    def _validate_height(self, height, unconfirmed_height, last_height):
        if last_height < 0:
            raise ValueError(f"Peer is bad. last({last_height})")
        if unconfirmed_height >= 0 and unconfirmed_height != (last_height + 1):
            raise ValueError(f"Peer is bad. unconfirmed({unconfirmed_height}) <= last({last_height})")

        expected_height = self._my_height + 1
        if height != expected_height:
            raise ValueError(f"Peer is bad. height({height}) != expected height({expected_height})")
        if height == unconfirmed_height and height <= self._last_height:
            raise ValueError(f"Peer is late. unconfirmed({unconfirmed_height}), last({self._last_height})")

    def _update_height(self, block: Block, unconfirmed_height, last_height):
        """Update block height information such as block height, unconfirmed block height and last block height
        :param block: Received block
        :param unconfirmed_height: Received last unconfirmed block height
        :param last_height: Received last block height
        :return: if True is returned, this block is available.
        """
        self._validate_height(block.header.height, unconfirmed_height, last_height)

        if last_height > self._last_height:
            utils.logger.spam(f"change last block height: {self._last_height} -> {last_height}"
                              f", unconfirmed block height: {self._unconfirmed_height} -> {unconfirmed_height}")
            self._last_height = last_height
            self._unconfirmed_height = unconfirmed_height
            self._max_height = max(last_height, unconfirmed_height)
        elif unconfirmed_height > self._unconfirmed_height:
            utils.logger.spam(f"change unconfirmed block height: {self._unconfirmed_height} -> {unconfirmed_height}")
            self._unconfirmed_height = unconfirmed_height
            self._max_height = unconfirmed_height

        if block.header.height == unconfirmed_height:
            self._unconfirmed_block = block
        else:
            self._unconfirmed_block = None

        return self._touched_every_stub or self._unconfirmed_block is None

    def _succeed(self):
        self._my_height += 1
        self._retry_number = 0

    def _failed(self):
        self._retry_number += 1
        utils.logger.warning(f"Block height({self._my_height}) synchronization is fail. "
                             f"{self._retry_number}/{configure.BLOCK_SYNC_RETRY_NUMBER}")
        if self._retry_number >= configure.BLOCK_SYNC_RETRY_NUMBER:
            utils.exit_and_msg(f"This peer already tried to synchronize {self._my_height} block "
                               f"for max retry number({configure.BLOCK_SYNC_RETRY_NUMBER}). "
                               f"Peer will be down.")

    def sync(self, prepare, block_handler):
        for peer_stub, next_height in self:
            if not prepare():
                return

            try:
                block, last_height, unconfirmed_height, confirm_info, response_code = \
                    self._block_request(peer_stub, next_height)
            except Exception as e:
                utils.logger.warning("There is a bad peer, I hate you: " + str(e))
                traceback.print_exc()
                response_code = message_code.Response.fail

            if response_code != message_code.Response.success:
                utils.logger.warning(f"Not responding peer({peer_stub}) is removed from the peer stubs target.")
                self._erase()
                continue

            utils.logger.debug(f"try add block height: {block.header.height}")

            try:
                available = self._update_height(block, unconfirmed_height, last_height)
                if not available:
                    continue
                elif self._unconfirmed_block is not None:
                    break
            except ValueError as e:
                utils.logger.warning(e)
                self._erase()
                continue

            try:
                result = False
                result = block_handler(block, confirm_info=confirm_info)
            except StopIteration:
                break
            finally:
                if result:
                    self._succeed()
                else:
                    self._failed()

        if self._unconfirmed_block is not None:
            block_handler(self._unconfirmed_block, is_unconfirmed_block=True)
