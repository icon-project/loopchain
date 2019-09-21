import functools
import time

import pytest

from testcase.integration.configure.config_generator import ConfigGenerator
from testcase.integration.helper.executor import Loopchain


@pytest.fixture
def config_factory(tmp_path):
    def _config_factory(root_path) -> ConfigGenerator:
        return ConfigGenerator(root_path=root_path)

    return functools.partial(_config_factory, root_path=tmp_path)


@pytest.fixture(scope="class")
def config_factory_class_scoped(tmp_path_factory):
    def _config_factory(root_path) -> ConfigGenerator:
        return ConfigGenerator(root_path=root_path)

    return functools.partial(_config_factory, root_path=tmp_path_factory.mktemp("test_dir", numbered=True))


@pytest.fixture(scope="class")
def loopchain():
    _loopchain = Loopchain()

    yield _loopchain

    # tear down
    for proc in _loopchain.proc_list:
        proc.terminate()

    time.sleep(3)  # Give CoolDown for additional tests
