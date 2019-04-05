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
"""A module of exceptions for errors on block chain"""

from loopchain.protos import message_code


class BlockInValidError(Exception):
    """블럭 검증오류
    검증되지 않은 블럭이 블럭체인에 추가되거나, 검증시 hash값이 다르다면 발생한다
    """
    pass


class BlockError(Exception):
    """블럭의 구성이 완벽하지 않거나, 구성요소의 일부분이 없을때 발생
    """
    pass


class BlockchainError(Exception):
    """블럭체인상에서 문제가 발생했을때 발생하는 에러
    """
    pass


class AddUnconfirmedBlock(Exception):
    """
    """
    pass


class BlockVersionNotMatch(Exception):
    def __init__(self, block_version: str, target_version: str, msg: str):
        super().__init__(msg)
        self.block_version = block_version
        self.target_version = target_version
        self.msg = msg

    def __str__(self):
        results = []
        if self.msg:
            results.append(self.msg)
        results.append(f"block version: {self.block_version}")
        results.append(f"target version: {self.target_version}")
        return ' '.join(results)


class ScoreInvokeError(Exception):
    """Error While Invoke Score
    """


class ChannelStatusError(Exception):
    """Channel is Dead
    """


class UnknownHashVersionError(Exception):
    def __init__(self, version, message=None):
        super(message)
        self.version = version

    def __str__(self):
        return f"{super().__str__()} version: {self.version}"


class MessageCodeError(Exception):
    message_code = None


class TransactionInvalidError(MessageCodeError):
    message_code = message_code.Response.fail_tx_invalid_unknown

    def __init__(self, tx_hash=None, message=''):
        super().__init__(message)
        self.tx_hash = tx_hash
        
    def __str__(self):
        return f"{super().__str__()} tx_hash: {self.tx_hash}"


class TransactionInvalidHashFormatError(TransactionInvalidError):
    message_code = message_code.Response.fail_tx_invalid_hash_format


class TransactionInvalidHashGenerationError(TransactionInvalidError):
    message_code = message_code.Response.fail_tx_invalid_hash_generation

    def __init__(self, tx_hash, origin_data, message=''):
        super().__init__(tx_hash, message)
        self.origin_data = origin_data

    def __str__(self):
        return f"{super().__str__()} origin_data: {self.origin_data}"


class TransactionInvalidHashNotMatchError(TransactionInvalidError):
    message_code = message_code.Response.fail_tx_invalid_hash_not_match

    def __init__(self, tx_hash, expected_tx_hash):
        super().__init__(tx_hash)
        self.excepted_tx_hash = expected_tx_hash

    def __str__(self):
        return f"{super().__str__()} expected_tx_hash: {self.excepted_tx_hash}"


class TransactionInvalidAddressNotMatchError(TransactionInvalidError):
    message_code = message_code.Response.fail_tx_invalid_address_not_match

    def __init__(self, tx_hash, address, expected_address):
        super().__init__(tx_hash)
        self.address = address
        self.expected_address = expected_address

    def __str__(self):
        return f"{super().__str__()} address: {self.address} expected_tx_hash: {self.expected_address}"


class TransactionInvalidAddressError(TransactionInvalidError):
    message_code = message_code.Response.fail_tx_invalid_address_format

    def __init__(self, tx_hash, address, message=''):
        super().__init__(tx_hash, message)
        self.address = address

    def __str__(self):
        return f"{super().__str__()} address: {self.address}"


class TransactionInvalidSignatureError(TransactionInvalidError):
    message_code = message_code.Response.fail_tx_invalid_signature

    def __init__(self, tx_hash, signature, address):
        super().__init__(tx_hash)
        self.signature = signature
        self.address = address

    def __str__(self):
        return f"{super().__str__()} address: {self.address} signature: {self.signature}"


class TransactionInvalidParamError(TransactionInvalidError):
    message_code = message_code.Response.fail_tx_invalid_params

    def __init__(self, tx_hash, origin_data, message=''):
        super().__init__(tx_hash, message)
        self.origin_data = origin_data

    def __str__(self):
        return f"{super().__str__()} origin_data: {self.origin_data}"


class TransactionInvalidDuplicatedHash(TransactionInvalidError):
    message_code = message_code.Response.fail_tx_invalid_duplicated_hash


class TransactionInvalidOutOfTimeBound(TransactionInvalidError):
    message_code = message_code.Response.fail_tx_invalid_out_of_time_bound

    def __init__(self, tx_hash, tx_timestamp, cur_timestamp, message=''):
        super().__init__(tx_hash, message)
        self.tx_timestamp = tx_timestamp
        self.cur_timestamp = cur_timestamp

    def __str__(self):
        return f"{super().__str__()} tx_timestamp: {self.tx_timestamp} cur_timestamp: {self.cur_timestamp}"


class TransactionInvalidNoNidError(TransactionInvalidError):
    message_code = message_code.Response.fail_tx_invalid_wrong_nid

    def __init__(self, tx_hash, nid, expected_nid, message=''):
        super().__init__(tx_hash, message)
        self.nid = nid
        self.expected_nid = expected_nid

    def __str__(self):
        return f"{super().__str__()} nid: {self.nid} expected_nid: {self.expected_nid}"
