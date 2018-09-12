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
""" A library module for development of Score"""

import leveldb
import logging
import os
import os.path as osp
import sqlite3
from enum import Enum, IntEnum
from typing import Dict

from loopchain import configure as conf, utils
from loopchain.baseservice import ObjectManager, Block
from loopchain.components import SingletonMetaClass
from loopchain.tools.score_helper.score_db_proxy import ScoreDbProxy


class ScoreDatabaseType(Enum):
    sqlite3 = 'sqlite3'
    leveldb = 'leveldb'


class LogLevel(IntEnum):
    ERROR = 0
    WARNING = 1
    INFO = 2
    DEBUG = 3


class ScoreHelper(metaclass=SingletonMetaClass):
    """Score 를 개발하기 위한 라이브러리"""
    __SCORE_DATABASE_STORAGE = conf.DEFAULT_SCORE_STORAGE_PATH

    def __init__(self):
        logging.debug("ScoreHelper init")

        self.peer_id = None
        self.__db_proxy_dict = {}  # type: Dict[str, ScoreDbProxy]
        self.__now_block: Block = None

    def load_database(self, score_id, database_type=ScoreDatabaseType.sqlite3):
        """it will remove late please usecase
        laod database

        :param score:
        :param database_type:
        :return:
        """
        # peer_id 별로 databases 를 변경 할 것인지?
        connection = None

        # Peer의 정보
        if database_type is ScoreDatabaseType.sqlite3:
            return self.__sqlite3_database(score_id)
        if database_type is ScoreDatabaseType.leveldb:
            return self.__leveldb_database(score_id)
        else:
            logging.error("Did not find score database type")

        return connection

    def Put(self, db_name: str, key: bytes, value: bytes):
        self.__get_db_proxy(db_name).Put(key, value)

    def Query(self, db_name: str, key: bytes):
        return self.__get_db_proxy(db_name).query_db.Get(key)

    def Get(self, db_name: str, key: bytes):
        return self.__get_db_proxy(db_name).Get(key)

    def Delete(self, db_name: str, key: bytes):
        self.__get_db_proxy(db_name).Delete(key)

    def __get_db_proxy(self, db_name):
        if isinstance(db_name, str):
            try:
                return self.__db_proxy_dict[db_name]
            except KeyError:
                self.__db_proxy_dict[db_name] = ScoreDbProxy(self.__leveldb_database(db_name))
                if self.__now_block is not None:
                    self.__db_proxy_dict[db_name].init_invoke(self.__now_block)
                return self.__db_proxy_dict[db_name]
        else:
            raise TypeError("db_name must be str")

    def commit_block_state(self, block_height, block_hash):
        """commit block state in db_proxy to db

        :return:
        """
        try:
            for db_name, db_proxy in self.__db_proxy_dict.items():
                db_proxy.commit_block(block_height, block_hash)
                logging.debug("commit all block state")
        except Exception as e:
            logging.error(f"score state commit error {e}")
            for db_name, db_proxy in self.__db_proxy_dict.items():
                try:
                    db_proxy.rollback_db()
                except Exception as e:
                    logging.exception(f"rollback db fail {e}")
                    utils.exit_and_msg("rollback db fail please clear db, and restart peer")
            utils.exit_and_msg("rollback db to before invoke block complete please reboot and sync block")
        # init
        for db_name, db_proxy in self.__db_proxy_dict.items():
            db_proxy.reset_block_state()
            db_proxy.reset_backup()

    def get_block_commit_state(self, block_height, block_hash):
        """get pre commit state

        :return:
        """
        block_pre_commit_state = {}  # {db_name_that_made_by_score:precommit_state}

        try:
            for db_name, db_proxy in self.__db_proxy_dict.items():
                block_pre_commit_state[db_name] = db_proxy.get_precommit_state(block_height, block_hash)
        except Exception as e:
            logging.error(f"get pre commit state error {e}")

        return block_pre_commit_state

    def reset_precommit_state(self, block_height, block_hash):
        """if block verify fail remove all block state

        :return:
        """
        for db_name, db_proxy in self.__db_proxy_dict.items():
            db_proxy.reset_precommit_state(block_height, block_hash)

    def reset_tx_state(self):
        """if tx verify fail remove all tx_state

        :return:
        """
        for db_name, db_proxy in self.__db_proxy_dict.items():
            db_proxy.reset_tx_state()

    def commit_tx_state(self):
        """commit tx state in db_prxoy to block_state

        :return:
        """
        for db_name, db_proxy in self.__db_proxy_dict.items():
            db_proxy.commit_tx()

    def log(self, channel: str, msg: str, log_level=LogLevel.DEBUG):
        """log info log with peer_id

        :param channel: channel name
        :param msg: log msg
        :param log_level: logging level
        :return:
        """
        log = f"peer_id: {self.peer_id}, channel: {channel}, msg: {msg}"

        if log_level == LogLevel.DEBUG:
            logging.debug(log)
        elif log_level == LogLevel.INFO:
            logging.info(log)
        elif log_level == LogLevel.WARNING:
            logging.warning(log)
        elif log_level == LogLevel.ERROR:
            logging.error(log)

    def __db_filepath(self, peer_id, score_id):
        """make Database Filepath

        :param peer_id: peer ID
        :param score_id: score ID
        :return: score database filepath
        """
        if not peer_id:
            raise RuntimeError("`peer_id` is not set in score_helper.")

        _score_database = osp.join(self.__SCORE_DATABASE_STORAGE, peer_id)
        _score_database = osp.abspath(_score_database)
        if not osp.exists(_score_database):
            os.makedirs(_score_database)
        _score_database = osp.join(_score_database, score_id)
        return _score_database

    def __sqlite3_database(self, score_id):
        """Sqlite3용 Database 생성

        :param score_info:
        :return:
        """
        _score_database = self.__db_filepath(self.peer_id, score_id)
        connect = sqlite3.connect(_score_database, check_same_thread=False)
        return connect

    def __leveldb_database(self, score_id):
        """Leveldb 용 Database 생성

        :param score_info:
        :return:
        """
        _score_database = self.__db_filepath(self.peer_id, score_id)
        try:
            return leveldb.LevelDB(_score_database, create_if_missing=True)
        except leveldb.LevelDBError:
            raise leveldb.LevelDBError("Fail To Create Level DB(path): %s", _score_database)

    def load_query_database(self, db_name):
        return self.__get_db_proxy(db_name).query_db

    def precommit_state(self):
        for db_name, db_proxy in self.__db_proxy_dict.items():
            db_proxy.precommit_block()
        logging.debug("precommit all state")

    def init_invoke(self, block: Block):
        self.__now_block = block
        for db_name, db_proxy in self.__db_proxy_dict.items():
            db_proxy.init_invoke(block)

    def change_block_hash(self, block_height, old_block_hash, new_block_hash):
        for db_name, db_proxy in self.__db_proxy_dict.items():
            db_proxy.change_block_hash(block_height, old_block_hash, new_block_hash)
