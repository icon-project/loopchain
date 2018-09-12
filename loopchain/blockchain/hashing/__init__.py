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

from typing import Dict

from loopchain import configure as conf
from loopchain.blockchain.exception import UnknownHashVersionError

from .hash_preprossesor import *
from .hash_origin_generator import *
from .hash_generator import *


def build_hash_generator(version, hash_prepocessor, salt):
    if version == 0:
        origin_generator = HashOriginGeneratorV0()
    elif version == 1:
        origin_generator = HashOriginGeneratorV1()
    else:
        raise UnknownHashVersionError(version)

    return HashGenerator(origin_generator, hash_prepocessor, salt)


def get_tx_hash_generator(channel):
    version = conf.CHANNEL_OPTION[channel]['tx_hash_version']

    try:
        tx_hash_generator = _tx_hash_generators[channel]
        if tx_hash_generator.origin_generator.version != version:
            del _tx_hash_generators[channel]
            raise KeyError(channel)
    except KeyError:
        tx_hash_generator = _tx_hash_generators[channel] = \
            build_hash_generator(version, HashPreprocessorSendTransaction(), "icx_sendTransaction")

    return tx_hash_generator


def get_genesis_tx_hash_generator(channel):
    version = conf.CHANNEL_OPTION[channel]['genesis_tx_hash_version']

    try:
        genesis_tx_hash_generator = _genesis_tx_hash_generators[channel]
        if genesis_tx_hash_generator.origin_generator.version != version:
            del _tx_hash_generators[channel]
            raise KeyError(channel)
    except KeyError:
        genesis_tx_hash_generator = _genesis_tx_hash_generators[channel] = \
            build_hash_generator(version, HashPreprocessor(), "genesis_tx")

    return genesis_tx_hash_generator


def get_vote_hash_generator(channel):
    version = conf.CHANNEL_OPTION[channel]['tx_hash_version']

    try:
        vote_hash_generator = _vote_hash_generators[channel]
        if vote_hash_generator.origin_generator.version != version:
            del _vote_hash_generators[channel]
            raise KeyError(channel)
    except KeyError:
        vote_hash_generator = _vote_hash_generators[channel] = \
            build_hash_generator(version, HashPreprocessor(), None)

    return vote_hash_generator


_tx_hash_generators: Dict[str, HashGenerator] = {}
_genesis_tx_hash_generators: Dict[str, HashGenerator] = {}
_vote_hash_generators: Dict[str, HashGenerator] = {}
