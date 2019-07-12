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

import abc
import grpc

from loopchain import configure as conf
from .grpc_secure_key import GRPCSecureKeyCollection


class GRPCConnector(abc.ABC):
    """
    A connector used in grpc is a component of the 'strategy pattern'.
    It abstracts and wraps 'grpc.add_port()' and 'grpc.channel()'
    """

    @classmethod
    @abc.abstractmethod
    def add_server_port(cls, keys: GRPCSecureKeyCollection, server, host, ssl_auth_type: conf.SSLAuthType):
        pass

    @classmethod
    @abc.abstractmethod
    def create_client_channel(cls, keys: GRPCSecureKeyCollection, host, ssl_auth_type: conf.SSLAuthType):
        pass


class GRPCConnectorInsecure(GRPCConnector):

    @classmethod
    def add_server_port(cls, keys: GRPCSecureKeyCollection, server, host, ssl_auth_type: conf.SSLAuthType):
        server.add_insecure_port(host)

    @classmethod
    def create_client_channel(cls, keys: GRPCSecureKeyCollection, host, ssl_auth_type: conf.SSLAuthType):
        return grpc.insecure_channel(host)


class GRPCConnectorServerOnly(GRPCConnector):

    @classmethod
    def add_server_port(cls, keys: GRPCSecureKeyCollection, server, host, ssl_auth_type: conf.SSLAuthType):
        credentials = grpc.ssl_server_credentials(
            [(keys.ssl_pk, keys.ssl_crt)],
            root_certificates=None,
            require_client_auth=False)
        server.add_secure_port(host, credentials)

    @classmethod
    def create_client_channel(cls, keys: GRPCSecureKeyCollection, host, ssl_auth_type: conf.SSLAuthType):
        credentials = grpc.ssl_channel_credentials(
            root_certificates=keys.ssl_root_crt)
        return grpc.secure_channel(host, credentials)


class GRPCConnectorMutual(GRPCConnector):

    @classmethod
    def add_server_port(cls, keys: GRPCSecureKeyCollection, server, host, ssl_auth_type: conf.SSLAuthType):
        credentials = grpc.ssl_server_credentials(
            [(keys.ssl_pk, keys.ssl_crt)],
            root_certificates=keys.ssl_root_crt,
            require_client_auth=True)
        server.add_secure_port(host, credentials)

    @classmethod
    def create_client_channel(cls, keys: GRPCSecureKeyCollection, host, ssl_auth_type: conf.SSLAuthType):
        credentials = grpc.ssl_channel_credentials(
            root_certificates=keys.ssl_root_crt,
            private_key=keys.ssl_pk,
            certificate_chain=keys.ssl_crt)
        return grpc.secure_channel(host, credentials)
