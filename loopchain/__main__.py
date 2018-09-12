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

import os
import sys

import yappi

from . import configure as conf
from . import launcher


def main():
    try:
        if os.getenv('DEFAULT_SCORE_HOST') is not None:
            os.system("ssh-keyscan "+os.getenv('DEFAULT_SCORE_HOST')+" >> /root/.ssh/known_hosts")

        if conf.ENABLE_PROFILING:
            yappi.start()
            launcher.main(sys.argv[1:])
            yappi.stop()
        else:
            launcher.main(sys.argv[1:])
    except KeyboardInterrupt:
        if conf.ENABLE_PROFILING:
            yappi.stop()
            print('Yappi result (func stats) ======================')
            yappi.get_func_stats().print_all()
            print('Yappi result (thread stats) ======================')
            yappi.get_thread_stats().print_all()


if __name__ == "__main__":
    main()
