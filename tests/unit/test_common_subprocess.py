"""Test Common Process"""

import logging
import time
import unittest

from loopchain.baseservice import CommonSubprocess
from loopchain.utils import loggers

loggers.set_preset_type(loggers.PresetType.develop)
loggers.update_preset()


class TestCommonSubprocess(unittest.TestCase):

    def test_common_subprocess(self):
        # GIVEN
        process_args = ['ls']
        logging.debug(f"run common subprocess....")
        subprocess = CommonSubprocess(process_args)
        logging.debug(f"after run common subprocess....")
        subprocess.start()
        subprocess.start()
        subprocess.start()
        self.assertTrue(subprocess.is_run())

        # WHEN
        time.sleep(2)
        subprocess.stop()
        subprocess.wait()
        subprocess.wait()
        subprocess.stop()

        # THEN
        self.assertFalse(subprocess.is_run())


if __name__ == '__main__':
    unittest.main()
