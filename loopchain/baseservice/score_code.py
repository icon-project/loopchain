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
""" Collection of codes used in the score"""

from enum import IntEnum


class ScoreResponse(IntEnum):
    """ Score Invoke Response Codes
    """
    SUCCESS = 0
    EXCEPTION = 9000
    NOT_INVOKED = 2  # means pending
    NOT_EXIST = 3  # considered fail
    SCORE_CONTAINER_EXCEPTION = 9100


class PrepChangedReason:
    TERM_END = "0x0"  # Term ends and reset P-Rep list
    PANELTY = "0x1"  # Updated within term (Panelty)
