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
"""base class for Singleton class"""


# Singleton/singleton.py
class SingletonMetaClass(type):
    """특정 클래스에서 metaclass 로 지정하면 해당 클래스는 singleton이 된다.
    사용예: class ClassOne(metaclass=SingletonMetaClass):
    """
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(SingletonMetaClass, cls).__call__(*args, **kwargs)

        return cls._instances[cls]

    def clear(cls):
        """testcase 에서 테스트 instance 를 반복해서 생성하는 경우
        singleton 규칙에서 예외로 한다. 실제 코드에서는 이 루틴을 호출해서는 안된다!!

        :param cls: Sigleton instance 의 class 이름
        """
        if cls in cls._instances:
            cls._instances.pop(cls)
