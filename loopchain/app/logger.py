import json
import coloredlogs
import logging
from functools import partial
from typing import Union
from lft.event import Event
from lft.serialization import Serializable

__all__ = ("Logger", )


class Logger:
    def __init__(self, node_id: bytes):
        self.logger = logging.getLogger(node_id.hex())

        style = coloredlogs.DEFAULT_LEVEL_STYLES.copy()
        style['debug'] = {'color': 'cyan'}
        coloredlogs.install(level='DEBUG', milliseconds=True, logger=self.logger,
                            fmt='%(asctime)s,%(msecs)03d %(message)s',
                            datefmt='%H:%M:%S',
                            level_styles=style)

        patcher = LoggerPatcher(self.logger, node_id)
        self.logger._debug = self.logger.debug
        self.logger._info = self.logger.info
        self.logger._warning = self.logger.warning
        self.logger._error = self.logger.error
        self.logger._critical = self.logger.critical
        self.logger._fatal = self.logger.fatal

        self.logger.debug = partial(patcher.log, "_debug")
        self.logger.info = partial(patcher.log, "_info")
        self.logger.warning = partial(patcher.log, "_warning")
        self.logger.critical = partial(patcher.log, "_critical")
        self.logger.fatal = partial(patcher.log, "_fatal")


class LoggerPatcher:
    def __init__(self, logger: logging.Logger, node_id: bytes):
        self._logger = logger
        self._node_id = node_id
        self._encoder = _JSONEncoder()

    def log(self, level: str, msg: Union[str, Event], *arg, **kwargs):
        if isinstance(msg, Event):
            msg = self._make_log(msg)

        msg = f"0x{shorten(self._node_id)} {msg}"
        logging_method = getattr(self._logger, level)
        logging_method(msg, *arg, **kwargs)

    def _make_log(self, event: Event):
        event_encoded = self._encoder.encode(event)
        event_serialized = json.loads(event_encoded)

        return self.__make_log(event_serialized)

    def __make_log(self, event):
        if isinstance(event, dict):
            if "!type" in event:
                type_ = event["!type"].split(".")[-1]
                if "!data" in event:
                    return f"{type_}{self.__make_log(event['!data'])}"
                else:
                    return f"{type_}"
            else:
                return "(" + ",".join(f"{k}={self.__make_log(v)}" for k, v in event.items()) + ")"
        elif isinstance(event, list):
            return "[" + ",".join(self.__make_log(item) for item in event) + "]"
        else:
            return f"{event}"


class _JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if not o:
            return "None"
        elif isinstance(o, bytes):
            return "0x" + shorten(o)
        elif isinstance(o, str):
            return "0r" + o
        elif isinstance(o, Serializable):
            return o.serialize()
        else:
            return super().encode(o)


def shorten(b: bytes):
    return b.hex()[:4]
