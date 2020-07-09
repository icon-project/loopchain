"""RPC Service for QA"""

import logging
import types
from threading import Thread
from typing import Callable

from rpyc.core import SlaveService
from rpyc.utils.server import ThreadedServer


DEFAULT_PORT = 18812


class QaService(SlaveService):
    def __init__(self):
        super(QaService, self).__init__()
        self.cs = None

    def on_connect(self, conn):
        # code that runs when a connection is created
        # (to init the service, if needed)
        super(QaService, self).on_connect(conn)
        logging.info(f"on_connect() : {conn}")

    def on_disconnect(self, conn):
        # code that runs after the connection has already closed
        # (to finalize the service, if needed)
        logging.info(f"on_disconnect() : {conn}")

    def set_channel_service(self, channel_service):
        self.cs = channel_service

    def monkey_patch(self, obj: object, func_target: str, func: Callable):
        logging.info(f"monkey_patch() : target = {func_target}")
        setattr(obj, func_target, types.MethodType(func, obj))


class QaThread:
    def __init__(self, service, port):
        self.tserver = None
        self.port = port

        t = Thread(target=self.run, args=(service,))
        t.start()

    def run(self, service):
        self.tserver = ThreadedServer(service, port=self.port)
        self.tserver.start()

    def close(self):
        logging.debug(f"close()")
        self.tserver.close()


qaservice = None
qathread = None


def run(port=DEFAULT_PORT):
    global qaservice, qathread
    qaservice = QaService()
    qathread = QaThread(qaservice, port)
