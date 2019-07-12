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
"""gRPC helper for security"""
import logging
from concurrent import futures

import grpc

from loopchain import configure as conf
from loopchain.components import SingletonMetaClass
from .grpc_connector import GRPCConnector, GRPCConnectorInsecure, GRPCConnectorServerOnly, GRPCConnectorMutual
from .grpc_secure_key import GRPCSecureKeyCollection

__all__ = ['GRPCHelper']


class GRPCHelper(metaclass=SingletonMetaClass):
    """
    gRPC helper class
    """

    def __init__(self):
        self.__connectors = {
            conf.SSLAuthType.none: GRPCConnectorInsecure,
            conf.SSLAuthType.server_only: GRPCConnectorServerOnly,
            conf.SSLAuthType.mutual: GRPCConnectorMutual
        }

        self.__keys = GRPCSecureKeyCollection()

    def start_outer_server(self, port: str = None) -> grpc.Server:
        outer_server = grpc.server(futures.ThreadPoolExecutor(conf.MAX_WORKERS, "GRPCOuterThread"))
        target_host = f'[::]:{port}'
        self.add_server_port(outer_server, target_host)
        logging.debug(f"outer target host = {target_host}")

        return outer_server

    def start_inner_server(self, port: str = None) -> grpc.Server:
        inner_service_port = f'{int(port) + conf.PORT_DIFF_INNER_SERVICE}'

        inner_server = grpc.server(futures.ThreadPoolExecutor(conf.MAX_WORKERS, "GRPCInnerThread"))
        target_host = conf.INNER_SERVER_BIND_IP + ':' + inner_service_port
        self.add_server_port(inner_server, target_host, conf.SSLAuthType.none)
        logging.debug(f"inner target host = {target_host}")

        return inner_server

    def add_server_port(self, server, host, ssl_auth_type: conf.SSLAuthType=None, key_load_type: conf.KeyLoadType=None):
        """

        :param server: grpc server object
        :param host: Target host you want to serve
        :param ssl_auth_type: It notices that which type of SSL auth is used. None : conf.GRPC_SSL_TYPE
        :param key_load_type: It determines where keys has to be loaded. None : conf.GRPC_SSL_KEY_LOAD_TYPE
        :return:
        """
        if ssl_auth_type is None:
            ssl_auth_type = conf.GRPC_SSL_TYPE

        if key_load_type is None:
            key_load_type = conf.GRPC_SSL_KEY_LOAD_TYPE

        self.__keys.reset(ssl_auth_type, key_load_type)

        connector: GRPCConnector = self.__connectors[ssl_auth_type]
        connector.add_server_port(self.__keys, server, host, ssl_auth_type)
        server.start()

        logging.info(f"Server now listen: {host}, secure level : {str(ssl_auth_type)}")

    def create_client_channel(self, host, ssl_auth_type: conf.SSLAuthType=None, key_load_type: conf.KeyLoadType=None):
        """

        :param host: Target host you want to connect
        :param ssl_auth_type: It notices that which type of SSL auth is used. None : conf.GRPC_SSL_TYPE
        :param key_load_type: It determines where keys has to be loaded. None : conf.GRPC_SSL_KEY_LOAD_TYPE
        :return: grpc channel
        """
        if ssl_auth_type is None:
            ssl_auth_type = conf.GRPC_SSL_TYPE

        if key_load_type is None:
            key_load_type = conf.GRPC_SSL_KEY_LOAD_TYPE

        self.__keys.reset(ssl_auth_type, key_load_type)

        connector: GRPCConnector = self.__connectors[ssl_auth_type]
        channel = connector.create_client_channel(self.__keys, host, ssl_auth_type)

        logging.info(f"Client Channel : {host}, secure level : {str(ssl_auth_type)}")

        return channel

