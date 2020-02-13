import logging
import os
import random
import threading
from typing import List, Tuple, Callable

import pytest
import time

from loopchain import configure
from loopchain.baseservice.tx_message import TxItem, TxMessages, TxMessagesQueue
from loopchain.blockchain import ExternalAddress, Transaction
from loopchain.blockchain.transactions import TransactionVersioner, TransactionBuilder
from loopchain.crypto.signature import Signer

Logger = logging.getLogger(__name__)


@pytest.fixture
def tx_item() -> Callable[[TransactionVersioner], Transaction]:
    def _tx_item(tx_versioner: TransactionVersioner) -> Transaction:
        test_signer = Signer.from_prikey(os.urandom(32))
        tx_builder = TransactionBuilder.new("0x3", "", tx_versioner)
        tx_builder.signer = test_signer
        tx_builder.to_address = ExternalAddress.new()
        tx_builder.step_limit = random.randint(0, 10000)
        tx_builder.value = random.randint(0, 10000)
        tx_builder.nid = 2
        tx: Transaction = tx_builder.build()
        return tx
    return _tx_item


@pytest.fixture
def tx_items(request, tx_item) -> List[Tuple[Transaction, TransactionVersioner]]:
    tx_versioner = TransactionVersioner()
    tx_params = []

    tx_count = request.param
    Logger.info(f"tx_count : {request.param}")

    for i in range(tx_count):
        tx: Transaction = tx_item(tx_versioner)
        # Logger.info(f"tx : {tx.raw_data}")
        tx_params.append((tx, tx_versioner))

    return tx_params


class TestTxMessages:
    tx_count = 50

    @pytest.mark.parametrize("tx_items", [tx_count], indirect=True)
    def test_tx_messages(self, tx_items: List[Tuple[Transaction, TransactionVersioner]]):

        # given
        tx_size = 0
        tx_messages = TxMessages()
        for tx_param in tx_items:
            tx_item = TxItem.create_tx_item(tx_param, 'icon_dex')
            tx_messages.append(tx_item)
            tx_size += len(tx_item)

        # when
        tx_total_size = tx_messages.size()
        tx_total_count = len(tx_messages)

        # then
        assert tx_total_count == self.tx_count
        assert tx_total_size == tx_size


class TestTxMessagesQueue:
    tx_count = 50

    def test_custom_tx_value(self, monkeypatch):
        # given custom max_tx_size and max_tx_count
        given_max_tx_size = 1024
        given_max_tx_count = 100

        monkeypatch.setattr(configure, "MAX_TX_SIZE_IN_BLOCK", given_max_tx_size)
        monkeypatch.setattr(configure, "MAX_TX_COUNT_IN_ADDTX_LIST", given_max_tx_count)
        Logger.info(f"MAX_TX_SIZE_IN_BLOCK : {configure.MAX_TX_SIZE_IN_BLOCK}")
        Logger.info(f"MAX_TX_COUNT_IN_ADDTX_LIST : {configure.MAX_TX_COUNT_IN_ADDTX_LIST}")

        # when create TxMessagesQueue instance
        queue = TxMessagesQueue()
        Logger.info(f"TxMessagesQueue : tx_size : {queue.max_tx_size}, tx_count : {queue.max_tx_count}")

        # then
        assert queue.max_tx_size == given_max_tx_size
        assert queue.max_tx_count == given_max_tx_count

    @pytest.mark.parametrize("tx_items", [tx_count], indirect=True)
    def test_tx_messages_queue(self, tx_items: List[Tuple[Transaction, TransactionVersioner]]):
        # given add 50 tx data to TxMessagesQueue
        queue = TxMessagesQueue(max_tx_size=10 * 1024, max_tx_count=21)

        for tx_param in tx_items:
            tx_item = TxItem.create_tx_item(tx_param, 'icon_dex')
            queue.append(tx_item)

        # when get TxMessages from TxMessagesQueue
        tx_messages: TxMessages = queue.pop()
        tx_total_size = tx_messages.size()
        tx_total_count = len(tx_messages)

        Logger.info(f"messages size : {tx_total_size}")
        Logger.info(f"messages count : {tx_total_count}")
        Logger.info(f"queue empty : {queue.empty()}")

        # then size less than max size or count less than max count
        assert (tx_total_size < queue.max_tx_size
                or tx_total_count < queue.max_tx_count)

        # when get messages
        messages = tx_messages.get_messages()

        # then messages count equals tx_total_count
        assert len(messages) == tx_total_count

    @pytest.mark.parametrize("tx_items", [tx_count], indirect=True)
    def test_tx_message_queue_thread_safe(self,
                                          tx_items: List[Tuple[Transaction, TransactionVersioner]],
                                          tx_item: Callable[[TransactionVersioner], Transaction]):
        # given
        assert_count = {'produce_count': 150, 'consume_count': 0}

        queue = TxMessagesQueue(max_tx_size=10 * 1024, max_tx_count=21)

        tx_versioner = TransactionVersioner()

        init_tx_count = len(tx_items)
        for tx_param in tx_items:
            init_tx_item = TxItem.create_tx_item(tx_param, 'icon_dex')
            queue.append(init_tx_item)

        # when produce new tx_item and consume tx_messages from queue
        def producer():
            for _ in range(assert_count.get('produce_count') - init_tx_count):
                tx = tx_item(tx_versioner)
                p_tx_item = TxItem.create_tx_item((tx, tx_versioner), 'icon_dex')
                queue.append(p_tx_item)
                Logger.info(f"producer() : queue = {queue}")

        def consumer():
            while True:
                tx_messages = queue.pop()

                assert_count['consume_count'] += len(tx_messages)
                Logger.info(f"consumer() : queue = {queue}, tx_messages({id(tx_messages)})")
                Logger.info(f"consume_count : {assert_count['consume_count']}")

                if queue.empty() and not thread_producer.is_alive():
                    break

                time.sleep(0.03)

        thread_producer = threading.Thread(target=producer)
        thread_consumer = threading.Thread(target=consumer, args=())

        thread_producer.start()
        thread_consumer.start()

        thread_producer.join()
        thread_consumer.join()

        # then
        assert assert_count.get('consume_count') == assert_count.get('produce_count')

    @pytest.mark.skip("test manually")
    @pytest.mark.parametrize("tx_items", [tx_count], indirect=True)
    def test_tx_message_queue_thread_safe_maxsize(self,
                                                  tx_items: List[Tuple[Transaction, TransactionVersioner]],
                                                  tx_item: Callable[[TransactionVersioner], Transaction]):
        # given maxsize 2
        assert_count = {'produce_count': 150, 'consume_count': 0}

        queue = TxMessagesQueue(maxsize=2, max_tx_size=10 * 1024, max_tx_count=21)

        tx_versioner = TransactionVersioner()

        init_tx_count = len(tx_items)
        for tx_param in tx_items:
            init_tx_item = TxItem.create_tx_item(tx_param, 'icon_dex')
            queue.append(init_tx_item)

        # when produce new tx_item and consume tx_messages from queue
        def producer():
            for _ in range(assert_count.get('produce_count') - init_tx_count):
                tx = tx_item(tx_versioner)
                p_tx_item = TxItem.create_tx_item((tx, tx_versioner), 'icon_dex')
                queue.append(p_tx_item)
                Logger.info(f"producer() : queue = {queue}")

        def consumer():
            while True:
                tx_messages = queue.pop()

                assert_count['consume_count'] += len(tx_messages)
                Logger.info(f"consumer() : queue = {queue}, tx_messages({id(tx_messages)})")
                Logger.info(f"consume_count : {assert_count['consume_count']}")

                if queue.empty() and not thread_producer.is_alive():
                    break

                time.sleep(0.03)

        thread_producer = threading.Thread(target=producer)
        thread_consumer = threading.Thread(target=consumer, args=())

        thread_producer.start()
        thread_consumer.start()

        thread_producer.join()
        thread_consumer.join()

        # then
        assert assert_count.get('consume_count') == assert_count.get('produce_count')
