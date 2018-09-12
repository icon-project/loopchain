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
"""DB Proxy for tx state save before commit"""

import copy
import leveldb
import logging
from typing import Dict

from loopchain import utils
from loopchain.blockchain import Block


class ScoreDbProxy:

    KEY_TYPE_ERROR_MSG = 'key must be byte-like data'
    KEY_VALUE_TYPE_ERROR_MSG = 'key and value must be byte-like data'
    KEY_LAST_BLOCK_HEIGHT = b'key committed last block height'
    BLOCK_HEIGHT_BYTES_LEN = 12

    DELETE_CODE = -99999
    NONE_CODE = -1

    def __init__(self, db_connection: leveldb.LevelDB):
        self.__precommit_state = {}  # type: Dict[int, Dict[str, Dict[bytes, bytes]]]
        """
        {
            {height} : {
                {block_hash} : {
                    {key} : {value}
                }
            }
        }
        """
        self.__db_connection: leveldb.LevelDB = db_connection
        self.__tx_apply_state = {}  # type: Dict[bytes, bytes]
        self.__block_apply_state = {}  # type: Dict[bytes, bytes]
        self.__backup = {}  # type: Dict[bytes, bytes]
        self.__query_db = QueryDbProxy(self.__db_connection)
        self.__now_precommit_state = None  # type: Dict[bytes, bytes]
        self.__now_block_height = 0
        self.__now_block_hash = ""

    @property
    def query_db(self):
        return self.__query_db

    def reset_tx_state(self):
        self.__tx_apply_state = {}

    def reset_block_state(self):
        self.reset_tx_state()
        self.__block_apply_state = {}

    def __check_commit_block_height(self, block_height):
        try:
            committed_last_block_height = int.from_bytes(
                self.__db_connection.Get(self.KEY_LAST_BLOCK_HEIGHT), byteorder='big')
            if block_height != (committed_last_block_height + 1):
                logging.debug(f"score_db_proxy:commit_block block_height mismatch! "
                              f"committed_last_block_height({committed_last_block_height}) "
                              f"block_height({block_height})")
                return False
        except KeyError as e:
            pass

        return True

    def init_invoke(self, block: Block):
        if not self.__check_commit_block_height(block.height):
            return

        if block.height-1 in self.__precommit_state:
            try:
                self.__now_precommit_state = self.__precommit_state[block.height-1][block.prev_block_hash]
            except KeyError as e:
                self.__now_precommit_state = {}
        else:
            self.__now_precommit_state = {}
        self.__now_block_height = block.height
        self.__now_block_hash = block.block_hash
        self.reset_block_state()

    def __commit_block_final(self, block_height):
        try:
            del self.__precommit_state[block_height]
        except KeyError:
            logging.info(f"no data precommit state {block_height}")
        logging.info(f"after precommit state : {self.__precommit_state}")
        self.reset_block_state()

    def commit_block(self, block_height, block_hash):

        if not self.__check_commit_block_height(block_height):
            self.__commit_block_final(block_height)
            return

        self.__create_backup(block_height, block_hash)
        try:
            batch = leveldb.WriteBatch()
            for key, value in self.__precommit_state[block_height][block_hash].items():
                if value == self.DELETE_CODE:
                    batch.Delete(key)
                else:
                    batch.Put(key, value)
            batch.Put(self.KEY_LAST_BLOCK_HEIGHT, block_height.to_bytes(self.BLOCK_HEIGHT_BYTES_LEN, byteorder='big'))
            self.__db_connection.Write(batch, sync=True)
        except Exception as e:
            logging.exception(f"write batch to score db cause: {e}")
            logging.error("try rollback db to before invoke block")
            try:
                self.rollback_db()
                logging.exception(f"rollback db Success")
            except Exception as e:
                logging.exception(f"rollback db fail cause: {e}")
                utils.exit_and_msg("rollback db fail please remove all db and reboot sync all block")

        self.__commit_block_final(block_height)

    def precommit_block(self):
        """ save block state to precommit state
        """
        if self.__now_block_height not in self.__precommit_state:
            self.__precommit_state[self.__now_block_height] = {}
        self.__precommit_state[self.__now_block_height][self.__now_block_hash] = copy.deepcopy(self.__block_apply_state)
        self.reset_block_state()

    def rollback_db(self):
        batch = leveldb.WriteBatch()
        logging.error(f"backup db : {self.__backup}")
        for key in self.__backup:
            backup_data = self.__backup[key]
            if backup_data == self.NONE_CODE:
                batch.Delete(key)
            else:
                batch.Put(key, backup_data)
        self.__db_connection.Write(batch)

    def change_block_hash(self, block_height, old_block_hash, new_block_hash):
        if old_block_hash != new_block_hash:
            precommit_state = self.__precommit_state[block_height][old_block_hash].copy()
            self.__precommit_state[block_height][new_block_hash] = precommit_state
            if self.__now_precommit_state is self.__precommit_state[block_height][old_block_hash]:
                utils.logger.spam("now precommit state change")
                self.__now_precommit_state = self.__precommit_state[block_height][new_block_hash]
            del self.__precommit_state[block_height][old_block_hash]

    def reset_backup(self):
        self.__backup = {}

    def __create_backup(self, block_height, block_hash):
        for key in self.__precommit_state[block_height][block_hash].keys():
            try:
                self.__backup[key] = self.__db_connection.Get(key)
            except KeyError as e:
                self.__backup[key] = self.NONE_CODE
            except Exception as e:
                logging.error(e)
                utils.exit_and_msg("create score db backup fail please reboot and sync block")

    def commit_tx(self):
        for key, value in self.__tx_apply_state.items():
            self.__block_apply_state[key] = value
        self.reset_tx_state()

    def Get(self, key: bytes):
        """ get value by key

        :param key: key (bytes)
        :return: value data
        :raise: TypeError : raise when key is not byte-like data
        :raise: KeyError : DB do not Have that Key
        """
        if not isinstance(key, bytes):
            raise TypeError(self.KEY_TYPE_ERROR_MSG)
        if self.__now_precommit_state is None:
            value = self.__tx_apply_state.get(key,
                                              self.__block_apply_state.get(key))
        else:
            value = self.__tx_apply_state.get(
                key, self.__block_apply_state.get(
                    key, self.__now_precommit_state.get(key)))

        if value == self.DELETE_CODE:
            raise KeyError
        elif value is None:
            value = self.__db_connection.Get(key)
            logging.debug(f"ENGINE-299 get value from db : {key} {value}")
            return value
        else:
            return value

    def Put(self, key: bytes, value: bytes):
        """ put key & value

        :param key: key (bytes)
        :param value: value (bytes)
        :raise TypeError: raise when key or value is not byte-like data
        """
        if not (isinstance(key, bytes) and isinstance(value, bytes)):
            raise TypeError(self.KEY_VALUE_TYPE_ERROR_MSG)
        else:
            self.__tx_apply_state[key] = value

    def Delete(self, key: bytes):
        """ remove data matching key

        :param key: key (bytes)
        :raise: TypeError : raise when key is not byte-like data
        :raise: KeyError : DB do not Have that Key
        """
        # for raise exception
        self.Get(key)
        self.__tx_apply_state[key] = self.DELETE_CODE

    def reset_precommit_state(self, block_height, block_hash):
        """ remove precommit state corresponding block_height

        :param block_height:
        :return:
        """
        try:
            del self.__precommit_state[block_height][block_hash]
        except KeyError:
            logging.debug("no data in precommit state")
        self.reset_block_state()

    def get_precommit_state(self, block_height, block_hash):
        try:
            precommit_state = self.__precommit_state[block_height][block_hash]
            return {key.hex(): value.hex() for key, value in precommit_state.items()}
        except KeyError:
            logging.debug("no data in precommit state")
            return {}


class QueryDbProxy:
    def __init__(self, db_connection: leveldb.LevelDB):
        self.__db_connection = db_connection

    def Get(self, key: bytes):
        """ get value by key

        :param key: key (bytes)
        :return: value data
        :raise: TypeError : raise when key is not byte-like data
        :raise: KeyError : DB do not Have that Key
        """
        if not isinstance(key, bytes):
            raise TypeError(ScoreDbProxy.KEY_TYPE_ERROR_MSG)
        return self.__db_connection.Get(key)
