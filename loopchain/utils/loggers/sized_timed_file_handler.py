# Copyright 2018 ICON Foundation
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


import time
from logging.handlers import TimedRotatingFileHandler, RotatingFileHandler


class SizedTimedRotatingFileHandler(TimedRotatingFileHandler, RotatingFileHandler):
    def __init__(self, filename, mode='a', max_bytes=0, backup_count=0,
                 encoding=None, delay=False, when='h', interval=1, utc=False):
        TimedRotatingFileHandler.__init__(
            self, filename=filename, when=when, interval=interval,
            backupCount=backup_count, encoding=encoding, delay=delay, utc=utc)

        RotatingFileHandler.__init__(self, filename=filename, mode=mode, maxBytes=max_bytes,
                                     backupCount=backup_count, encoding=encoding, delay=delay)

    def computeRollover(self, current_time):
        return TimedRotatingFileHandler.computeRollover(self, current_time)

    def doRollover(self):
        # get from logging.handlers.TimedRotatingFileHandler.doRollover()
        current_time = int(time.time())
        dst_now = time.localtime(current_time)[-1]
        new_rollover_at = self.computeRollover(current_time)

        while new_rollover_at <= current_time:
            new_rollover_at = new_rollover_at + self.interval

        # If DST changes and midnight or weekly rollover, adjust for this.
        if (self.when == 'MIDNIGHT' or self.when.startswith('W')) and not self.utc:
            dst_at_rollover = time.localtime(new_rollover_at)[-1]
            if dst_now != dst_at_rollover:
                if not dst_now:  # DST kicks in before next rollover, so we need to deduct an hour
                    addend = -3600
                else:  # DST bows out before next rollover, so we need to add an hour
                    addend = 3600
                new_rollover_at += addend
        self.rolloverAt = new_rollover_at

        return RotatingFileHandler.doRollover(self)

    def shouldRollover(self, record):
        return TimedRotatingFileHandler.shouldRollover(self, record) or RotatingFileHandler.shouldRollover(self, record)
