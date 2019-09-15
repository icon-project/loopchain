import json
import subprocess
import time
from typing import List, Optional

import requests

from testcase.integration.configure.config_generator import ConfigGenerator


class Loopchain:
    def __init__(self):
        self._proc_list: List[subprocess.Popen] = []

    @property
    def proc_list(self) -> List[subprocess.Popen]:
        return self._proc_list

    def run(self, config: ConfigGenerator, rs_target=None) -> bool:
        for k, peer_config in enumerate(config.peer_config_list, start=1):
            cmd = ["loop", "-d", "-o", peer_config.path]
            if rs_target:
                cmd.extend(["-r", rs_target])
            print("Run loopchain cmd: ", cmd)

            proc = subprocess.Popen(cmd)
            self._proc_list.append(proc)

            endpoint = f"http://localhost:{peer_config.rest_port}/api/v1/avail/peer"
            channel_names = config.peer_config_list[0].channel_name_list

            for channel in channel_names:
                assert _ensure_run(endpoint=endpoint, channel_name=channel)

        print(f"==========ALL GREEN ==========")
        time.sleep(3)  # WarmUp before test starts

        return True


def _ensure_run(endpoint: str, channel_name: str, max_retry=60):
    interval_sleep_sec = 1
    retry_count = 0
    is_success = False

    while not is_success:
        if retry_count >= max_retry:
            break
        time.sleep(interval_sleep_sec)
        retry_count += 1

        response = _request_service_available(endpoint, channel_name, timeout=interval_sleep_sec)
        if not response:
            continue

        if response["service_available"]:
            is_success = True

    print("is_success?: ", is_success)
    return is_success


def _request_service_available(endpoint, channel_name:str, timeout=1) -> Optional[dict]:
    exc = None
    try:
        response = requests.get(endpoint, params={"channel": channel_name}, timeout=timeout)
        response = response.json()
    except (requests.exceptions.ConnectionError,
            requests.exceptions.ReadTimeout,
            json.JSONDecodeError) as e:
        exc = e
        response = None

    print(f"\n\n\n\nTEST>> {exc or response}")
    return response


