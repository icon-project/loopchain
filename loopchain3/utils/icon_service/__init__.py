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

from typing import Any
from jsonrpcserver import status
from loopchain.jsonrpc.exception import GenericJsonRpcServerError

from .converter import convert_params, ParamType


def check_error_response(result: Any):
    return isinstance(result, dict) and result.get('error')


def response_to_json_query(response, is_convert: bool = False):
    if check_error_response(response):
        response = response['error']
        raise GenericJsonRpcServerError(
            code=-response['code'],
            message=response['message'],
            http_status=status.HTTP_BAD_REQUEST
        )
    else:
        if is_convert:
            response = {
                'response': response,
                "response_code": 0
            }

    return response


def make_request(method, params, request_type=None):
    raw_request = {
        "method": method,
        "params": params
    }

    return convert_params(raw_request, request_type)
