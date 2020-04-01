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
"""base class for Score"""

import logging
from abc import ABCMeta, abstractmethod


class ScoreBase(metaclass=ABCMeta):
    """Score Base Class
    검증이 완료된 Block안의 Transaction을 실행합니다.
    """
    PACKAGE_FILE = 'package.json'

    def __init__(self, score_info=None):
        self._score_info = score_info

    def genesis_invoke(self, transaction, block=None):
        """검증이 끝난 Genesis block의 DATA를 추가 합니다.

        :param transaction: Transaction
        :param block: 해당 Block
        :return:
        """
        pass

    @abstractmethod
    def invoke(self, transaction, block):
        """검증이 완료된 블럭의 DATA를 추가 합니다.

        :param transaction: Transaction
        :param block: 해당 Block
        """
        pass

    @abstractmethod
    def query(self, params):
        """내부 DATA를 조회합니다.

        :param params: json string 으로 query 에 대한 parameter 를 입력받는다.
        :return: 결과 역시 json string 으로 응답 되어야 한다.
        """
        pass

    @abstractmethod
    def info(self):
        """Score 정보를 조회합니다.

        :return: 결과는 json object 로 응답한다.
        """
        pass

    def get_info_value(self, key):
        if self._score_info is not None:
            try:
                return self._score_info[key]
            except KeyError:
                logging.warning("There is no key in your score info, your key was: " + str(key))
        return ""
