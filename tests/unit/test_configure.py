"""Test Configure class"""

import logging
import unittest
from pathlib import Path

from loopchain import configure as conf
from loopchain import configure_default as conf_default
from loopchain.utils import loggers
from tests.unit import test_util

loggers.set_preset_type(loggers.PresetType.develop)
loggers.update_preset()


class TestConfigure(unittest.TestCase):

    def setUp(self):
        test_util.print_testname(self._testMethodName)

    def tearDown(self):
        pass

    def test_get_configure(self):
        logging.debug(f"conf.IP_LOCAL: {conf.IP_LOCAL}")
        self.assertEqual(conf.IP_LOCAL, conf_default.IP_LOCAL)

        logging.debug(f"conf.GRPC_TIMEOUT: {conf.GRPC_TIMEOUT}")
        self.assertTrue(isinstance(conf.GRPC_TIMEOUT, int))

        logging.debug(f"conf.LEVEL_DB_KEY_FOR_PEER_LIST: {conf.LEVEL_DB_KEY_FOR_PEER_LIST}")
        self.assertEqual(conf.LEVEL_DB_KEY_FOR_PEER_LIST, conf_default.LEVEL_DB_KEY_FOR_PEER_LIST)

    def test_load_configure_json(self):
        # GIVEN
        ip_local_before_load_json = conf.IP_LOCAL
        logging.debug(f"before json file load, conf.IP_LOCAL({ip_local_before_load_json})")

        test_configure_json_path = "configure_json_for_test.json"
        configure_json_file = Path(test_configure_json_path)
        if not configure_json_file.is_file():
            test_configure_json_path = "tests/unit/configure_json_for_test.json"

        # WHEN
        conf.Configure().load_configure_json(test_configure_json_path)
        logging.debug(f"after json file load, conf.IP_LOCAL({conf.IP_LOCAL})")

        # THEN
        self.assertNotEqual(ip_local_before_load_json, conf.IP_LOCAL)

        # BACK
        conf.IP_LOCAL = ip_local_before_load_json

    def test_is_support_node_function(self):
        # GIVEN
        community_node = conf.NodeType.CommunityNode
        citizen_node = conf.NodeType.CitizenNode

        # THEN
        self.assertTrue(conf.NodeType.is_support_node_function(conf.NodeFunction.Vote, community_node))
        self.assertFalse(conf.NodeType.is_support_node_function(conf.NodeFunction.Vote, citizen_node))
        self.assertTrue(conf.NodeType.is_support_node_function(conf.NodeFunction.Block, community_node))
        self.assertTrue(conf.NodeType.is_support_node_function(conf.NodeFunction.Block, citizen_node))


if __name__ == '__main__':
    unittest.main()
