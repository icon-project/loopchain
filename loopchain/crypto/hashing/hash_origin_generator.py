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

import abc
import copy


class HashOriginGenerator(abc.ABC):
    version = None

    @abc.abstractmethod
    def generate(self, origin_data: dict) -> str:
        pass


class HashOriginGeneratorV0(HashOriginGenerator):
    version = 0

    def generate(self, origin_data: dict):
        copied_origin_data = copy.deepcopy(origin_data)
        gen = self.__gen_origin_str(copied_origin_data)
        return ".".join(gen)

    def __gen_origin_str(self, origin_data: dict):
        ordered_keys = list(origin_data)
        ordered_keys.sort()
        for key in ordered_keys:
            yield key
            if isinstance(origin_data[key], str):
                yield origin_data[key]
            elif isinstance(origin_data[key], dict):
                yield from self.__gen_origin_str(origin_data[key])
            elif isinstance(origin_data[key], list):
                for data in origin_data[key]:
                    yield from self.__gen_origin_str(data)
            else:
                raise TypeError(f"{key} must be dict or str")


class HashOriginGeneratorV1(HashOriginGenerator):
    version = 1

    _translator = str.maketrans({
        "\\": "\\\\",
        "{": "\\{",
        "}": "\\}",
        "[": "\\[",
        "]": "\\]",
        ".": "\\."
    })

    def generate(self, json_data: dict):

        def encode(data):
            if isinstance(data, dict):
                return encode_dict(data)
            elif isinstance(data, list):
                return encode_list(data)
            else:
                return escape(data)

        def encode_dict(data: dict):
            result = ".".join(_encode_dict(data))
            return "{" + result + "}"

        def _encode_dict(data: dict):
            for key in sorted(data.keys()):
                yield key
                yield encode(data[key])

        def encode_list(data: list):
            result = ".".join(_encode_list(data))
            return f"[" + result + "]"

        def _encode_list(data: list):
            for item in data:
                yield encode(item)

        def escape(data):
            if data is None:
                return "\\0"

            data = str(data)
            return data.translate(self._translator)

        return ".".join(_encode_dict(json_data))
