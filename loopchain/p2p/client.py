""" p2p Client """

import abc


class P2PClientBase(abc.ABC):
    """Peer to Peer Client abstract class
    """

    @abc.abstractmethod
    def connect(self):
        raise NotImplementedError("connect")

    @abc.abstractmethod
    def call_sync(self):
        raise NotImplementedError("call sync")

    @abc.abstractmethod
    def call_async(self):
        raise NotImplementedError("call async")

    @abc.abstractmethod
    def close(self):
        raise NotImplementedError("close")


class GrpcClient(P2PClientBase):
    """
    Peer to Peer gRPC Client
    """

    def __int__(self):
        pass

    def connect(self):
        pass

    def call_sync(self):
        pass

    def call_async(self):
        pass

    def close(self):
        pass


class ZeromqClient(P2PClientBase):
    """
    Peer to Peer zeroMQ Client
    """

    def __init__(self):
        pass

    def connect(self):
        pass

    def call_sync(self):
        pass

    def call_async(self):
        pass

    def close(self):
        pass


class P2PClient:
    """
    p2p network communication client
    """

    def __init__(self):
        pass


