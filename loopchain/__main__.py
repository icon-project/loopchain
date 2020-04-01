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

import sys

import yappi

from legacy import launcher as launcher2
from loopchain import launcher as launcher3
from loopchain import utils
from loopchain.blockchain.exception import ConsensusChanged
from . import configure as conf


def launch(argv):
    try:
        launcher2.main(argv)
    except ConsensusChanged as e:
        utils.logger.info(f"Consensus Changed")
        utils.logger.info(f"Remain txs. {len(e.remain_txs)}")
        utils.logger.info(f"Last unconfirmed block {e.last_unconfirmed_block and e.last_unconfirmed_block.header}")
        utils.logger.info(f"Last unconfirmed votes {e.last_unconfirmed_votes}")
        launcher3.main(argv)


def main():
    try:
        if conf.ENABLE_PROFILING:
            yappi.start()
            launch(sys.argv[1:])
            yappi.stop()
        else:
            launch(sys.argv[1:])
    except KeyboardInterrupt:
        if conf.ENABLE_PROFILING:
            yappi.stop()
            print('Yappi result (func stats) ======================')
            yappi.get_func_stats().print_all()
            print('Yappi result (thread stats) ======================')
            yappi.get_thread_stats().print_all()


if __name__ == "__main__":
    main()
