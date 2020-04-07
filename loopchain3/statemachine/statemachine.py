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

from transitions.extensions import LockedMachine as Machine

import loopchain.utils as util


class ExceptionNullStatesInMachine(Exception):
    pass


class ExceptionNullInitState(Exception):
    pass


class StateMachine(object):
    def __init__(self, arg):
        self.arg = arg
        util.logger.spam(f"arg is {self.arg}")

    def __call__(self, cls):
        class Wrapped(cls):
            attributes = self.arg

            def __init__(self, *cls_args):
                if not hasattr(cls, 'states') or not cls.states:
                    raise ExceptionNullStatesInMachine

                if not hasattr(cls, 'init_state') or not cls.init_state:
                    raise ExceptionNullInitState

                util.logger.spam(f"Wrapped __init__ called")
                util.logger.spam(f"cls_args is {cls_args}")
                # self.name = "superman"

                cls.machine = Machine(model=self, states=cls.states, initial=cls.init_state,
                                      ignore_invalid_triggers=True)

                cls.__init__(self, *cls_args)

                for attr_name in dir(cls):
                    attr = getattr(cls, attr_name, None)
                    if not attr:
                        continue

                    info_dict = getattr(attr, "_info_dict_", None)
                    if not info_dict:
                        continue

                    self.machine.add_transition(attr.__name__, **info_dict)

        return Wrapped


def transition(**kwargs_):
    def _transaction(func):
        func._info_dict_ = kwargs_
        return func

    return _transaction
