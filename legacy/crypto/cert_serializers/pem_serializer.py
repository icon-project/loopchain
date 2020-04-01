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

from legacy.crypto.cert_serializers import Serializer
from cryptography.hazmat.primitives import serialization


class PemSerializer(Serializer):
    encoding = serialization.Encoding.PEM

    @classmethod
    def load_private_key(cls, cert_private_key: bytes, password, backend):
        return serialization.load_pem_private_key(cert_private_key, password, backend)

    @classmethod
    def load_public_key(cls, cert_public_key: bytes, backend):
        return serialization.load_pem_public_key(cert_public_key, backend)
