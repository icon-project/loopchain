import json
from pathlib import Path

import pytest

from loopchain.tools.config_gen.helper import Key
from loopchain.tools.config_gen.helper import check_param_exist, dict_write
from loopchain.tools.config_gen.helper import make_genesis_data


class TestConfigHelper:
    def test_accounts_in_genesis_data_matches_key_address(self, tmp_path):
        key_count = 8
        key_password = "password"
        keys = [Key(path=tmp_path / f"key{i}.json", password=key_password)
                for i in range(key_count)]
        genesis_data = make_genesis_data(keys=keys)

        accounts = genesis_data["transaction_data"]["accounts"]
        for key, account in zip(keys, accounts):
            assert account["address"] == key.address


class TestOtherHelper:
    @pytest.mark.parametrize("attr_name", ["keys", "syek"])
    def test_decorator_works(self, attr_name):
        class TargetClass:
            @check_param_exist(attr_name=attr_name)
            def method(self):
                return True

        cls = TargetClass()
        setattr(cls, attr_name, None)
        assert not getattr(cls, attr_name)

        with pytest.raises(RuntimeError, match=f"build_{attr_name}"):
            cls.method()

        setattr(cls, attr_name, "value")
        cls.method()

    def test_dict_write_works(self, tmp_path):
        expected_path: Path = tmp_path / "file_name.json"
        expected_dict = {
            "this": {
                "will": [
                    "be", "written", "as", "json", "file"
                ]
            }
        }
        assert not expected_path.exists()

        dict_write(expected_path, expected_dict)
        assert expected_path.exists()

        with open(str(expected_path), "r", encoding="utf-8") as f:
            deserialized_dict = json.load(f)

        assert expected_dict == deserialized_dict

    def test_dict_write_failed_if_already_exists(self, tmp_path):
        expected_path: Path = tmp_path / "file_name.json"
        expected_dict = {
            "this": "test"
        }

        dict_write(expected_path, expected_dict)
        with pytest.raises(FileExistsError):
            dict_write(expected_path, expected_dict)
