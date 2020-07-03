#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2017 theloop Inc.
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
"""Test Score Invoke and Query"""
"""Temporary Skip("LFT")
"""

"""
import logging
import unittest

from loopchain.consensus import Subscriber, Publisher

from ..unit import test_util
from loopchain.utils import loggers


loggers.set_preset_type(loggers.PresetType.develop)
loggers.update_preset()
loggers.update_other_loggers()


class TestEventSystem(unittest.TestCase):

    def setUp(self):
        test_util.print_testname(self._testMethodName)

    def tearDown(self):
        pass

    def test_subscriber_register(self):
        publisher = self.get_default_subscribers()

        self.assertEqual(len(publisher.event_list), 4)
        self.assertEqual(len(publisher.event_list["a"]), 4)
        self.assertEqual(len(publisher.event_list["b"]), 3)
        self.assertEqual(len(publisher.event_list["c"]), 1)

        return publisher

    def test_subscriber_unregister(self):
        publisher = self.get_default_subscribers()
        publisher.unregister_subscriber("a", self.__callback_for_test_order_10)
        self.assertEqual(len(publisher.event_list["a"]), 3)
        self.assertEqual(len(publisher.event_list["b"]), 3)

    def test_subscriber_unregister_all_events(self):
        publisher = self.get_default_subscribers()
        publisher.unregister_subscriber("c", self.__callback_for_test_order_7)
        self.assertEqual(publisher.event_list.get("c"), None)

    def test_notify(self):
        publisher = self.get_default_subscribers()

        publisher._notify("a")
        logging.debug("----------------------------")
        publisher._notify("b")
        logging.debug("----------------------------")
        publisher._notify("c")
        logging.debug("----------------------------")

    def test_none_callback(self):
        publisher = self.get_default_subscribers()
        publisher._notify("d")

    def get_default_subscribers(self):
        subscriber_1 = Subscriber("s1")
        subscriber_1.event_list = [("a", self.__callback_for_test_order_5, 5)]
        subscriber_2 = Subscriber("s2")
        subscriber_2.event_list = [
            ("a", self.__callback_for_test_order_10, 10),
            ("b", self.__callback_for_test_order_5, 5)
        ]
        subscriber_3 = Subscriber("s3")
        subscriber_3.event_list = [
            ("a", self.__callback_for_test_order_1, 1),
            ("b", self.__callback_for_test_order_7, 7)
        ]

        subscriber_4 = Subscriber("s4")
        subscriber_4.event_list = [
            ("a", self.__callback_for_test_order_999, 999),
            ("b", self.__callback_for_test_order_10, 10),
            ("c", self.__callback_for_test_order_7, 7),
            ("d", None, 1)
        ]

        publisher = TestEventSystem.PublisherTest(["a", "b", "c", "d"])
        publisher.register_subscriber(subscriber_1)
        publisher.register_subscriber(subscriber_2)
        publisher.register_subscriber(subscriber_3)
        publisher.register_subscriber(subscriber_4)

        return publisher

    def __callback_for_test_order_1(self, name: str):
        logging.debug(f"{name}:1")

    def __callback_for_test_order_5(self, name: str):
        logging.debug(f"{name}:5")

    def __callback_for_test_order_7(self, name: str):
        logging.debug(f"{name}:7")

    def __callback_for_test_order_10(self, name: str):
        logging.debug(f"{name}:10")

    def __callback_for_test_order_999(self, name: str):
        logging.debug(f"{name}:999")

    class PublisherTest(Publisher):
        def __init__(self, event_list: list):
            super().__init__(event_list)

        def _notify(self, event_name: str):
            kwargs = {"name": event_name}
            super()._notify(event_name=event_name, **kwargs)
"""
