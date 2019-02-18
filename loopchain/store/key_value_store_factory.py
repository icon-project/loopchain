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

from loopchain import configure as conf
from loopchain import utils
from loopchain.store.key_value_store import KeyValueStore
from loopchain.store.key_value_store_dict import KeyValueStoreDict
from loopchain.store.key_value_store_leveldb import KeyValueStoreLevelDb
from loopchain.store.key_value_store_plyvel import KeyValueStorePlyvel


class KeyValueStoreFactory:
    STORE_TYPE_PLYVEL = 'plyvel'
    STORE_TYPE_LEVELDB = 'leveldb'
    STORE_TYPE_DICT = 'dict'

    @staticmethod
    def new(uri: str, store_type: str=None, **kwargs) -> KeyValueStore:
        if store_type is None:
            store_type = conf.DEFAULT_KEY_VALUE_STORE_TYPE

        utils.logger.info(f"New KeyValueStore. store_type={store_type}, uri={uri}")

        if store_type == KeyValueStoreFactory.STORE_TYPE_PLYVEL:
            utils.logger.debug(f"New KeyValueStorePlyvel.")
            return KeyValueStorePlyvel(uri, **kwargs)
        elif store_type == KeyValueStoreFactory.STORE_TYPE_LEVELDB:
            utils.logger.warning(f"New KeyValueStoreLevelDb. store_type={store_type}, uri={uri}")
            return KeyValueStoreLevelDb(uri, **kwargs)
        elif store_type == KeyValueStoreFactory.STORE_TYPE_DICT:
            raise ValueError(f"KeyValueStoreDict is just for development.")
            return KeyValueStoreDict(uri, **kwargs)
        else:
            raise ValueError(f"store_name is invalid. store_type={store_type}")
