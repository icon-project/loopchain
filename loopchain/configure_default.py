"""It use setting default value about configure. It can set directly value or use export."""

import os
import sys

from enum import IntEnum, IntFlag, auto


LOOPCHAIN_ROOT_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
PATH_PROTO_BUFFERS = "loopchain/protos"
PATH_PROTO_BUFFERS_TEST = "../../loopchain/protos"

if os.path.exists(PATH_PROTO_BUFFERS):
    sys.path.append(PATH_PROTO_BUFFERS)
else:
    sys.path.append(PATH_PROTO_BUFFERS_TEST)


#############
# LOGGING ###
#############
class LogOutputType(IntFlag):
    console = auto()
    file = auto()


LOOPCHAIN_LOG_LEVEL = os.getenv('LOOPCHAIN_LOG_LEVEL', 'DEBUG')
LOOPCHAIN_DEVELOP_LOG_LEVEL = "SPAM"
LOOPCHAIN_OTHER_LOG_LEVEL = "WARNING"
LOG_FORMAT = "%(asctime)s,%(msecs)03d %(process)d %(thread)d {PEER_ID} {CHANNEL_NAME} " \
             "%(levelname)s %(filename)s(%(lineno)d) %(message)s"

LOG_OUTPUT_TYPE = LogOutputType.console | LogOutputType.file

LOG_FILE_LOCATION = os.path.join(LOOPCHAIN_ROOT_PATH, 'log')
LOG_FILE_PREFIX = "loopchain"
LOG_FILE_EXTENSION = "log"

LOG_FILE_ROTATE_WHEN = ''  # Default '', Do no rotate log files by time
LOG_FILE_ROTATE_INTERVAL = 1

LOG_FILE_ROTATE_MAX_BYTES = 0  # Default 0, Do not rotate log files by max bytes

LOG_FILE_ROTATE_BACKUP_COUNT = 10
LOG_FILE_ROTATE_UTC = False


###################
# MULTI PROCESS ###
###################
ENABLE_PROFILING = False
SUB_PROCESS_JOIN_TIMEOUT = 30
IS_BROADCAST_MULTIPROCESSING = False


##########
# GRPC ###
##########
class SSLAuthType(IntEnum):
    none = 0
    server_only = 1
    mutual = 2


class KeyLoadType(IntEnum):
    FILE_LOAD = 0
    KMS_LOAD = 1
    RANDOM_TABLE_DERIVATION = 2


IP_LOCAL = '127.0.0.1'
IP_BLOCKGENERATOR = IP_LOCAL
IP_PEER = IP_LOCAL
IP_RADIOSTATION = IP_LOCAL
IP_RADIOSTATION_SUB = IP_LOCAL
INNER_SERVER_BIND_IP = '127.0.0.1'
DOCKER_HOST = os.getenv('DOCKER_HOST')
LOOPCHAIN_HOST = os.getenv('LOOPCHAIN_HOST', DOCKER_HOST)

PORT_PEER = 7100
PORT_INNER_SERVICE = 0
PORT_DIFF_INNER_SERVICE = 10000  # set inner_service_port to (peer_service_port + this value)
PORT_BLOCKGENERATOR = 7101
PORT_RADIOSTATION = 7102
PORT_RADIOSTATION_SUB = 7102
PORT_DIFF_SCORE_CONTAINER = 20021  # peer service 가 score container 를 시작할 때 자신과 다른 포트를 사용하도록 차이를 설정한다.
PORT_DIFF_BETWEEN_SCORE_CONTAINER = 30
MAX_WORKERS = 8
MAX_BROADCAST_WORKERS = 1
SLEEP_SECONDS_IN_SERVICE_LOOP = 0.1  # 0.05  # multi thread 동작을 위한 최소 대기 시간 설정
SLEEP_SECONDS_IN_SERVICE_NONE = 2  # _아무일도 하지 않는 대기 thread 의 대기 시간 설정
GRPC_TIMEOUT = 30  # seconds
GRPC_TIMEOUT_SHORT = 5  # seconds
GRPC_TIMEOUT_BROADCAST_RETRY = 6  # seconds
GRPC_TIMEOUT_TEST = 30  # seconds
GRPC_CONNECTION_TIMEOUT = GRPC_TIMEOUT * 2  # seconds, Connect Peer 메시지는 처리시간이 좀 더 필요함
STUB_REUSE_TIMEOUT = 60  # minutes

GRPC_SSL_TYPE = SSLAuthType.none
GRPC_SSL_KEY_LOAD_TYPE = KeyLoadType.FILE_LOAD
GRPC_SSL_DEFAULT_CERT_PATH = 'resources/ssl_test_cert/ssl.crt'
GRPC_SSL_DEFAULT_KEY_PATH = 'resources/ssl_test_cert/ssl.key'
GRPC_SSL_DEFAULT_TRUST_CERT_PATH = 'resources/ssl_test_cert/root_ca.crt'


###################
# BLOCK MANAGER ###
###################
class ConsensusAlgorithm(IntEnum):
    none = 0
    default = 1
    siever = 2
    lft = 3


INTERVAL_BLOCKGENERATION = 2
INTERVAL_BROADCAST_SEND_UNCONFIRMED_BLOCK = INTERVAL_BLOCKGENERATION
MAX_MADE_BLOCK_COUNT = 10
WAIT_SECONDS_FOR_VOTE = 0.2
# blockchain 용 level db 생성 재시도 횟수, 테스트가 아닌 경우 1로 설정하여도 무방하다.
MAX_RETRY_CREATE_DB = 10
# default key value store type
DEFAULT_KEY_VALUE_STORE_TYPE = "plyvel"
# default level db path
DEFAULT_LEVEL_DB_PATH = "./db"
# peer_id (UUID) 는 최초 1회 생성하여 level db에 저장한다.
LEVEL_DB_KEY_FOR_PEER_ID = str.encode("peer_id_key")
# String Peer Data Encoding
PEER_DATA_ENCODING = 'UTF-8'
# Hash Key Encoding
HASH_KEY_ENCODING = 'UTF-8'
# Consensus Algorithm
CONSENSUS_ALGORITHM = ConsensusAlgorithm.siever

# 블럭의 최대 크기 (kbytes), gRPC 최대 메시지는 4MB (4096) 이므로 그보다 작게 설정할 것
MAX_BLOCK_KBYTES = 3000  # default: 3000
# The total size of the transactions in a block.
MAX_TX_SIZE_IN_BLOCK = 1 * 1024 * 1024  # 1 MB is better than 2 MB (because tx invoke need CPU time)
MAX_TX_COUNT_IN_ADDTX_LIST = 128  # AddTxList can send multiple tx in one message.
SEND_TX_LIST_DURATION = 0.3  # seconds
# Consensus Vote Ratio 1 = 100%, 0.5 = 50%
VOTING_RATIO = 0.67  # for Add Block
LEADER_COMPLAIN_RATIO = 0.51  # for Leader Complain
# Block Height 를 level_db 의 key(bytes)로 변환할때 bytes size
BLOCK_HEIGHT_BYTES_LEN = 12
# Block vote timeout
BLOCK_VOTE_TIMEOUT = 60 * 5  # seconds
CANDIDATE_BLOCK_TIMEOUT = 60 * 60  # seconds
# default storage path
DEFAULT_STORAGE_PATH = os.getenv('DEFAULT_STORAGE_PATH', os.path.join(LOOPCHAIN_ROOT_PATH, '.storage'))
# max tx list size by address
TX_LIST_ADDRESS_PREFIX = b'tx_list_by_address_'
MAX_TX_LIST_SIZE_BY_ADDRESS = 100
MAX_PRE_VALIDATE_TX_CACHE = 10000
TIMESTAMP_BOUNDARY_SECOND = 60 * 15
# Some older clients have a process that treats tx, which is delayed by more than 30 minutes, as a failure.
# The engine limits the timestamp of tx to a lower value.
TIMESTAMP_BUFFER_IN_VERIFIER = int(0.3 * 1_000_000)  # 300ms (as microsecond)

MAX_TX_QUEUE_AGING_SECONDS = 60 * 5
INVOKE_RESULT_AGING_SECONDS = 60 * 60
SAFE_BLOCK_BROADCAST = True


class SendTxType(IntEnum):
    pickle = 0
    json = 1
    icx = 2
    genesis_block = 3


RUN_ICON_IN_LAUNCHER = False


##################
# REST SERVICE ###
##################
PORT_DIFF_REST_SERVICE_CONTAINER = 1900  # peer service 가 REST container 를 시작할 때 자신과 다른 포트를 사용하도록 차이를 설정한다.
PORT_PEER_FOR_REST = PORT_PEER + PORT_DIFF_REST_SERVICE_CONTAINER
ENABLE_REST_SERVICE = True
REST_SSL_TYPE = SSLAuthType.none
REST_SSL_VERIFY = True
DEFAULT_SSL_CERT_PATH = 'resources/ssl_test_cert/ssl.crt'
DEFAULT_SSL_KEY_PATH = 'resources/ssl_test_cert/ssl.key'
DEFAULT_SSL_TRUST_CERT_PATH = 'resources/ssl_test_cert/root_ca.crt'
REST_TIMEOUT = 5
REST_ADDITIONAL_TIMEOUT = 30  # seconds
GUNICORN_WORKER_COUNT = int(os.cpu_count() * 0.5) or 1


class ApiVersion(IntEnum):
    node = 1
    v1 = 2
    v2 = 3
    v3 = 4


##########
# Peer ###
##########
CONNECTION_RETRY_INTERVAL = 2  # seconds
CONNECTION_RETRY_INTERVAL_TEST = 2  # seconds for testcase
CONNECTION_RETRY_TIMEOUT_WHEN_INITIAL = 5  # seconds
CONNECTION_RETRY_TIMEOUT = 60  # seconds
CONNECTION_RETRY_TIMEOUT_TO_RS = 60 * 5  # seconds
CONNECTION_RETRY_TIMEOUT_TO_RS_TEST = 30  # seconds for testcase
CONNECTION_RETRY_TIMES = 3
BROADCAST_RETRY_TIMES = 1
RELAY_RETRY_TIMES = 3
REQUEST_BLOCK_GENERATOR_TIMEOUT = 10  # seconds
BLOCK_GENERATOR_BROADCAST_TIMEOUT = 5  # seconds
WAIT_GRPC_SERVICE_START = 5  # seconds
WAIT_SECONDS_FOR_SUB_THREAD_START = 5  # seconds
SLEEP_SECONDS_FOR_SUB_PROCESS_START = 1  # seconds
WAIT_SUB_PROCESS_RETRY_TIMES = 5
INTERVAL_SECONDS_PROCESS_MONITORING = 30  # seconds
PEER_NAME = "no_name"
IS_BROADCAST_ASYNC = True
SUBSCRIBE_LIMIT = 10
SUBSCRIBE_RETRY_TIMER = 14
SHUTDOWN_TIMER = 60 * 120
GET_LAST_BLOCK_TIMER = 30
BLOCK_SYNC_RETRY_NUMBER = 5
TIMEOUT_FOR_LEADER_COMPLAIN = 60
MAX_TIMEOUT_FOR_LEADER_COMPLAIN = 300
CITIZEN_ASYNC_RESULT_MAX_SIZE = 10_000_000  # dictionary Length
CITIZEN_ASYNC_REQUEST_RETRY_TIMES = 20
CITIZEN_ASYNC_REQUEST_WAIT = 3  # seconds



class NodeFunction(IntEnum):
    Block = 1 << 0  # 1
    Vote = 1 << 1  # 2
    Full = Block | Vote  # 3


class NodeType(IntEnum):
    CommunityNode = NodeFunction.Full  # 3
    CitizenNode = NodeFunction.Full ^ NodeFunction.Vote  # 1

    @classmethod
    def is_support_node_function(cls, node_function, node_type):
        if (node_type & node_function) == node_function:
            return True
        return False


##################
# RadioStation ###
##################
LEVEL_DB_KEY_FOR_PEER_LIST = "peer_manager_key"
SLEEP_SECONDS_IN_RADIOSTATION_HEARTBEAT = 15   # 60 * 60  # seconds, RS 의 peer status heartbeat 주기
# How many non-response will allow. After this count RS. will delete that node in network.
NO_RESPONSE_COUNT_ALLOW_BY_HEARTBEAT = 5
# How many non-response will allow if node is leader. After this count RS. will select new leader in network.
NO_RESPONSE_COUNT_ALLOW_BY_HEARTBEAT_LEADER = 1
CONNECTION_RETRY_TIMER = SLEEP_SECONDS_IN_RADIOSTATION_HEARTBEAT * 2 + 2  # The duration of the ConnectPeer timer by peer.
# If disconnected state of the peer is maintained, That peer will removed from peer list after this minutes.
RADIO_STATION_NAME = "RadioStation"
LOOPCHAIN_DEFAULT_CHANNEL = "icon_dex"  # Default Channel Name
LOOPCHAIN_TEST_CHANNEL = "loopchain_test"
CHANNEL_MANAGE_DATA_PATH = os.path.join(LOOPCHAIN_ROOT_PATH, 'channel_manage_data.json')  # Channel Manage Data Path
ENABLE_CHANNEL_AUTH = True  # if this option is true, peer only gets channel infos to which it belongs.
CHANNEL_RESTART_TIMEOUT = 120
CHANNEL_BUILTIN = True


########
# MQ ###
########
AMQP_TARGET = "127.0.0.1"
AMQP_USERNAME = os.getenv("AMQP_USERNAME", "guest")
AMQP_PASSWORD = os.getenv("AMQP_PASSWORD", "guest")
AMQP_CONNECTION_ATTEMPTS = 32
AMQP_RETRY_DELAY = 5
PEER_QUEUE_NAME_FORMAT = "Peer.{amqp_key}"
CHANNEL_QUEUE_NAME_FORMAT = "Channel.{channel_name}.{amqp_key}"
CHANNEL_TX_CREATOR_QUEUE_NAME_FORMAT = "ChannelTxCreator.{channel_name}.{amqp_key}"
CHANNEL_TX_RECEIVER_QUEUE_NAME_FORMAT = "ChannelTxReceiver.{channel_name}.{amqp_key}"
SCORE_QUEUE_NAME_FORMAT = "Score.{score_package_name}.{channel_name}.{amqp_key}"
ICON_SCORE_QUEUE_NAME_FORMAT = "IconScore.{channel_name}.{amqp_key}"
AMQP_KEY_DEFAULT = "amqp_key"
AMQP_KEY = AMQP_KEY_DEFAULT


###############
# Signature ###
###############
CHANNEL_OPTION = {
    LOOPCHAIN_DEFAULT_CHANNEL: {
        "block_versions": {
            "0.1a": 0,
            "0.3": 1
        },
        "hash_versions": {
            "genesis": 1,
            "0x2": 1,
            "0x3": 1
        },
        "load_cert": False,
        "consensus_cert_use": False,
        "tx_cert_use": False,
        "key_load_type": KeyLoadType.FILE_LOAD,
        "crep_root_hash": ""
    },
    LOOPCHAIN_TEST_CHANNEL: {
        "block_versions": {
            "0.1a": 0,
            "0.3": 1
        },
        "hash_versions": {
            "genesis": 1,
            "0x2": 1,
            "0x3": 1
        },
        "load_cert": False,
        "consensus_cert_use": False,
        "tx_cert_use": False,
        "key_load_type": KeyLoadType.FILE_LOAD,
        "crep_root_hash": ""
    }
}

PRIVATE_PATH = ""
PRIVATE_PASSWORD = None

# KMS
KMS_AGENT_PASSWORD = ""
KMS_TLS_KEY_ID = ""
KMS_SECRET_KEY_LABEL = "KEY_ENCRYPTION"


####################
# TimerService ###
####################
TIMEOUT_FOR_PEER_VOTE = 20
TIMEOUT_FOR_PEER_BLOCK_GENERATION = TIMEOUT_FOR_PEER_VOTE + 10

TIMEOUT_FOR_PEER_INIT = 60
TIMEOUT_FOR_RS_INIT = 60

NO_TIMEOUT_FOR_PEER_INIT = -1
NO_TIMEOUT_FOR_RS_INIT = -1

TIMEOUT_FOR_FUTURE = 30
TIMEOUT_FOR_WS_HEARTBEAT = 30

TIMEOUT_FOR_BLOCK_MONITOR = 14
SLEEP_SECONDS_FOR_INIT_COMMON_PROCESS = 0.5


####################
# There are two strategy for block generation in loopchain.
# ALLOW_MAKE_EMPTY_BLOCK = False
# One is treat tx immediately and make Block also.
# But if there is no tx, loopchain is wait tx without repeated empty block generation.
# ALLOW_MAKE_EMPTY_BLOCK = True
# Another is make Block repeat whether tx is or not.
# This Option can effect that strategy.
####################
ALLOW_MAKE_EMPTY_BLOCK = True


####################
# ICON ####
####################
URL_CITIZEN_TESTNET = 'https://test-ctz.solidwallet.io'
URL_CITIZEN_MAINNET = 'https://ctz.solidwallet.io'
CONF_PATH_LOOPCHAIN_TESTNET = os.path.join(LOOPCHAIN_ROOT_PATH, 'conf/testnet/loopchain_conf.json')
CONF_PATH_LOOPCHAIN_MAINNET = os.path.join(LOOPCHAIN_ROOT_PATH, 'conf/mainnet/loopchain_conf.json')
CONF_PATH_ICONSERVICE_DEV = os.path.join(LOOPCHAIN_ROOT_PATH, 'conf/develop/iconservice_conf.json')
CONF_PATH_ICONSERVICE_TESTNET = os.path.join(LOOPCHAIN_ROOT_PATH, 'conf/testnet/iconservice_conf.json')
CONF_PATH_ICONSERVICE_MAINNET = os.path.join(LOOPCHAIN_ROOT_PATH, 'conf/mainnet/iconservice_conf.json')
CONF_PATH_ICONRPCSERVER_DEV = os.path.join(LOOPCHAIN_ROOT_PATH, 'conf/develop/iconrpcserver_conf.json')
CONF_PATH_ICONRPCSERVER_TESTNET = os.path.join(LOOPCHAIN_ROOT_PATH, 'conf/testnet/iconrpcserver_conf.json')
CONF_PATH_ICONRPCSERVER_MAINNET = os.path.join(LOOPCHAIN_ROOT_PATH, 'conf/mainnet/iconrpcserver_conf.json')
ICON_VERSIONS = {
    'loopchain': '0.0.0',
    'iconservice': '0.0.0',
    'iconrpcserver': '0.0.0',
    'iconcommons': '0.0.0',
    'earlgrey': '0.0.0',
    'icon_rc': '0.0.0'
}

####################
# QOS ####
####################
TPS_LIMIT_PER_SEC = 1000
