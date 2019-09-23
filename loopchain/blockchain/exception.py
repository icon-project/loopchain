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

from typing import TYPE_CHECKING

from loopchain.protos import message_code

if TYPE_CHECKING:
    from loopchain.blockchain.transactions import Transaction
    from loopchain.blockchain.types import Hash32


class InvalidBlock(Exception):
    """Raise when an invalid block tries to be added.
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


class NotEnoughVotes(Exception):
    """Consensus loop needs more time to collect votes.
    """
    pass


class ConfirmInfoInvalid(Exception):
    """Unconfirmed block has not valid confirm info for prev block.
    """
    pass


class ConfirmInfoInvalidNeedBlockSync(Exception):
    """Unconfirmed block has valid confirm info but it has higher height.
    """
    pass


class ConfirmInfoInvalidAddedBlock(Exception):
    """Unconfirmed block has valid confirm info but it has already added height.
    """
    pass


class InvalidUnconfirmedBlock(Exception):
    """
    """
    pass


class DuplicationUnconfirmedBlock(Exception):
    """
    """
    pass


class NotInReps(Exception):
    """
    """
    pass


class ThereIsNoCandidateBlock(Exception):
    """
    """
    pass


class CandidateBlockHeightError(Exception):
    """
    """
    pass


class AnnounceNewBlockError(Exception):
    message_code = message_code.Response.fail_announce_block


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
    message_code = message_code.Response.fail_score_invoke


class ScoreInvokeResultError(ScoreInvokeError):
    """Score Invoke Result Error
    """
    message_code = message_code.Response.fail_score_invoke_result


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


class NodeInitializationError(MessageCodeError):
    message_code = message_code.Response.fail_create_tx

    def __init__(self, tx_hash=None, message=''):
        super().__init__(message)
        self.tx_hash = tx_hash

    def __str__(self):
        return f"{super().__str__()} tx_hash: {self.tx_hash} Node initialization is not completed."


class TransactionInvalidError(MessageCodeError):
    message_code = message_code.Response.fail_tx_invalid_unknown

    def __init__(self, tx: 'Transaction', message=''):
        super().__init__(message)
        self.tx = tx
        
    def __str__(self):
        return \
            f"{super().__str__()}\n" \
            f"Transaction: {self.tx}"


class TransactionInvalidHashError(TransactionInvalidError):
    message_code = message_code.Response.fail_tx_invalid_hash_not_match

    def __init__(self, tx: 'Transaction', expected_tx_hash: 'Hash32', message=''):
        super().__init__(tx, message)
        self.excepted_tx_hash = expected_tx_hash

    def __str__(self):
        return \
            f"{super().__str__()}\n" \
            f"Expected hash: {self.excepted_tx_hash.hex_0x()}"


class TransactionInvalidSignatureError(TransactionInvalidError):
    message_code = message_code.Response.fail_tx_invalid_signature


class TransactionDuplicatedHashError(TransactionInvalidError):
    message_code = message_code.Response.fail_tx_invalid_duplicated_hash


class TransactionOutOfTimeBound(TransactionInvalidError):
    message_code = message_code.Response.fail_tx_invalid_out_of_time_bound

    def __init__(self, tx: 'Transaction', cur_timestamp: int, message=''):
        super().__init__(tx, message)
        self.cur_timestamp = cur_timestamp

    def __str__(self):
        return \
            f"{super().__str__()}\n" \
            f"Current_timestamp: {self.cur_timestamp}"


class TransactionInvalidNidError(TransactionInvalidError):
    message_code = message_code.Response.fail_tx_invalid_wrong_nid

    def __init__(self, tx: 'Transaction', expected_nid: int, message=''):
        super().__init__(tx, message)
        self.expected_nid = expected_nid

    def __str__(self):
        return \
            f"{super().__str__()}" \
            f"expected_nid: {self.expected_nid}"
