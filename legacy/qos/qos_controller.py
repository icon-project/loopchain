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

import abc
import time

from legacy import utils as util


class QosControl(abc.ABC):
    @abc.abstractmethod
    def limit(self):
        raise NotImplementedError("limit() function is interface method")


class QosCountControl(QosControl):
    def __init__(self, limit_count: int, interval: float=1.0):
        assert limit_count > 0 and interval > 0.0
        self._interval = interval
        self._limit_count = limit_count
        self._start: float = time.monotonic()
        self._count: int = 0

    def limit(self):
        monotonic = time.monotonic()
        diff = monotonic - self._start

        if diff > self._interval:
            self._start = monotonic
            self._count = 0
        elif self._count == self._limit_count:
            return True

        self._count += 1
        return False


class QosController:
    def __init__(self):
        self._controls = []

    def append(self, control: QosControl):
        assert control is not None
        if control in self._controls:
            util.logger.warning(f"The control has already been appended. control={control}")
            return
        self._controls.append(control)

    def remove(self, control: QosControl):
        try:
            self._controls.remove(control)
        except ValueError:
            util.logger.warning(f"The control has not been appended. control={control}")

    def limit(self):
        for control in self._controls:
            if control.limit():
                return True
        return False
