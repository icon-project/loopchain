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

from pathlib import Path

from loopchain import configure as conf


class GRPCSecureKeyCollection:
    """
    A class keeping secure keys containing SSL private key, SSL certificate, SSL CA(Root) certificate
    """

    @property
    def ssl_pk(self) -> bytes:
        return self.__ssl_pk.data

    @property
    def ssl_crt(self) -> bytes:
        return self.__ssl_crt.data

    @property
    def ssl_root_crt(self) -> bytes:
        return self.__ssl_root_crt.data

    def __init__(self):
        self.__ssl_pk = GRPCSecureKey()
        self.__ssl_crt = GRPCSecureKey()
        self.__ssl_root_crt = GRPCSecureKey()

        self.__curr_key_load_type: conf.KeyLoadType = None

    def reset(self, ssl_auth_type: conf.SSLAuthType, key_load_type: conf.KeyLoadType, force=False):
        """
        Reset keys if needed

        :param ssl_auth_type: It notices that which type of SSL auth is used.
        :param key_load_type: It determines where keys has to be loaded.
        :param force: Use this flag True. if keys muse be loaded regardless of caching.
        :return:
        """
        if ssl_auth_type == conf.SSLAuthType.none:
            return

        if key_load_type == conf.KeyLoadType.FILE_LOAD:
            self.__reset_by_file(force)

        elif key_load_type == conf.KeyLoadType.KMS_LOAD:
            self.__reset_by_kms(key_load_type, force)

        else:
            raise Exception(f'Not supported KeyLoadType : {str(key_load_type)}')

        self.__curr_key_load_type = key_load_type

    def __reset_by_file(self, force=False):
        self.__ssl_pk.reset_by_path(conf.GRPC_SSL_DEFAULT_KEY_PATH, force)
        self.__ssl_crt.reset_by_path(conf.GRPC_SSL_DEFAULT_CERT_PATH, force)
        self.__ssl_root_crt.reset_by_path(conf.GRPC_SSL_DEFAULT_TRUST_CERT_PATH, force)

    def __reset_by_kms(self, key_load_type: conf.KeyLoadType, force=False):
        from loopchain.tools.kms_helper import KmsHelper
        if not force and self.__curr_key_load_type == key_load_type:
            return

        cert_data, key_data = KmsHelper().get_tls_cert_pair()

        self.__ssl_pk.reset_by_data(key_data)
        self.__ssl_crt.reset_by_data(cert_data)
        self.__ssl_root_crt.reset_by_path(conf.GRPC_SSL_DEFAULT_TRUST_CERT_PATH, force)


class GRPCSecureKey:

    @property
    def data(self) -> bytes:
        return self.__data

    def __init__(self):
        self.__path: str = None
        self.__data: bytes = None

    def reset_by_data(self, data: bytes):
        if data is None:
            raise Exception(f'GRPCSecureKey Data is None')

        self.__data = data
        self.__path = None

    def reset_by_path(self, path: str, force=False):
        if path is None:
            raise Exception(f'GRPCSecureKey Path is None')

        if not force and path == self.__path:
            return

        if not Path(path).is_file():
            raise Exception(f'CRPCSecureKey Cannot read file : {path}')

        with open(path, 'rb') as file:
            self.__data = file.read()
            self.__path = path
