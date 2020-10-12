"""Test Utils Util"""

import unittest

import loopchain.utils as util
from loopchain.utils import loggers
from tests.unit import test_util

loggers.set_preset_type(loggers.PresetType.develop)
loggers.update_preset()


class TestUtilsUtil(unittest.TestCase):

    def setUp(self):
        test_util.print_testname(self._testMethodName)

    def tearDown(self):
        pass

    def test_parse_target_list(self):
        # GIVEN
        target_a_string = "111.222.333.444:1234"
        targets_string = "111.222.333.444:1234, 100.200.300.400:1000"

        # WHEN
        target_ip_and_port = util.parse_target_list(target_a_string)[0]
        target_list = util.parse_target_list(targets_string)

        # THEN
        self.assertEqual(target_ip_and_port[0], "111.222.333.444")
        self.assertEqual(target_ip_and_port[1], 1234)

        self.assertEqual(target_list[0][0], "111.222.333.444")
        self.assertEqual(target_list[0][1], 1234)

        self.assertEqual(target_list[1][0], "100.200.300.400")
        self.assertEqual(target_list[1][1], 1000)


if __name__ == '__main__':
    unittest.main()
