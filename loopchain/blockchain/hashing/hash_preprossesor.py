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
import copy

from loopchain import utils


class HashPreprocessor:
    def preprocess(self, origin_data) -> dict:
        copied_origin_data = copy.deepcopy(origin_data)
        return copied_origin_data


class HashPreprocessorSendTransaction(HashPreprocessor):
    def preprocess(self, origin_data):
        copied_origin_data = copy.deepcopy(origin_data)

        tx_hash_key = utils.get_tx_hash_key(origin_data)
        if tx_hash_key in copied_origin_data:
            del copied_origin_data[tx_hash_key]

        if 'method' in copied_origin_data:
            del copied_origin_data['method']

        if 'signature' in copied_origin_data:
            del copied_origin_data['signature']

        return copied_origin_data
