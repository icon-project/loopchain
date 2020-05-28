from queue import Queue
from typing import List, Any

from loopchain import configure


class TxMessages:
    def __init__(self):
        self._total_size: int = 0
        self._messages: List['TxSend'] = []

    def __len__(self):
        return len(self._messages)

    def append(self, tx_item):
        self._messages.append(tx_item.get_tx_message())
        self._total_size += len(tx_item)

    def get_messages(self) -> List['TxSend']:
        return self._messages

    def size(self) -> int:
        return self._total_size


class TxMessagesQueue(Queue):
    """TXMessagesQueue is blocking queue

    enqueue item to queue 'append()'
    dequeue item from queue 'pop()'
    """

    def __init__(self, maxsize=0, max_tx_size=None, max_tx_count=None):
        super().__init__(maxsize=maxsize)
        self.max_tx_size = max_tx_size or configure.MAX_TX_SIZE_IN_BLOCK
        self.max_tx_count = max_tx_count or configure.MAX_TX_COUNT_IN_ADDTX_LIST

        self._tx_messages = TxMessages()

    def __str__(self):
        return (f"{self.__class__.__name__}(queue={self.qsize()}, "
                f"tx_count={len(self._tx_messages)})")

    def append(self, tx_item: Any):
        with self.not_full:
            tx_total_size = self._tx_messages.size() + len(tx_item)
            tx_total_count = len(self._tx_messages) + 1

            if tx_total_size >= self.max_tx_size or tx_total_count >= self.max_tx_count:
                if self.maxsize > 0:
                    while self._qsize() >= self.maxsize:
                        self.not_full.wait()

                self._put(self._tx_messages)
                self._tx_messages = TxMessages()
                self.unfinished_tasks += 1

            self._tx_messages.append(tx_item)
            self.not_empty.notify()

    def pop(self) -> TxMessages:
        with self.not_empty:
            while not (self._qsize() or len(self._tx_messages)):
                self.not_empty.wait()

            if not self._qsize():
                tx_messages = self._tx_messages
                self._tx_messages = TxMessages()
            else:
                tx_messages = self._get()
                self.not_full.notify()

            return tx_messages

    def empty(self) -> bool:
        with self.mutex:
            return not self._qsize() and len(self._tx_messages) <= 0

    def put(self, item, block=True, timeout=False) -> None:
        """Put is not supported to prevent block and timeout parameter

        use append() method instead of put()
        """
        raise NotImplementedError

    def get(self, block=True, timeout=None) -> None:
        """Get is not supported to prevent block and timeout parameter

        use pop() method instead of get()
        """
        raise NotImplementedError

    def put_nowait(self, item) -> None:
        """Put without blocking is not supported
        """
        raise NotImplementedError

    def get_nowait(self) -> None:
        """Get without blocking is not supported
        """
        raise NotImplementedError
