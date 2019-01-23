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

import hashlib

from .hash_origin_generator import HashOriginGenerator


class HashGenerator:
    def __init__(self, origin_generator: HashOriginGenerator, salt=None):
        self.origin_generator = origin_generator
        self.salt = salt

    def generate_salted_origin(self, origin_data: dict):
        def _gen():
            if self.salt is not None:
                yield self.salt
            yield self.origin_generator.generate(origin_data)
        return '.'.join(_gen())

    def generate_hash(self, origin_data: dict):
        origin = self.generate_salted_origin(origin_data)
        return hashlib.sha3_256(origin.encode()).digest()
