#!/usr/bin/env python
# -*- coding: utf-8 -*-

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
import random
import unittest

import loopchain.utils as util
import tests.unit.test_util as test_util
from loopchain.statemachine import statemachine


@statemachine.StateMachine("State Machine")
class StateMachinedHero(object):
    states = ['asleep', 'hanging out', 'hungry', 'sweaty', 'saving the world']
    init_state = 'asleep'

    def __init__(self, name):
        util.logger.spam(f"StateMachinedHero __init__ called")

        self.name = name
        self.kittens_rescued = 0

        # use self.machine for full functions of transitions
        self.machine.add_transition('clean_up', 'sweaty', 'asleep', conditions=['is_exhausted'])
        self.machine.add_transition('clean_up', 'sweaty', 'hanging out')

    # use decorator for typical transitions
    @statemachine.transition(source='asleep', dest='hanging out')
    def wake_up(self):
        pass

    @statemachine.transition(source='hanging out', dest='hungry')
    def work_out(self):
        pass

    @statemachine.transition(source='hungry', dest='hanging out')
    def eat(self):
        pass

    @statemachine.transition(source='*', dest='saving the world',
                             before='change_into_super_secret_costume')
    def distress_call(self):
        pass

    @statemachine.transition(source='saving the world', dest='sweaty',
                             after='update_journal')
    def complete_mission(self):
        pass

    @statemachine.transition(source='*', dest='asleep')
    def nap(self):
        pass

    def clean_up(self):
        print(f"\n\nStateMachinedHero::clean_up is replaced by add_transition!")
        raise Exception

    def update_journal(self):
        """ Dear Diary, today I saved Mr. Whiskers. Again. """
        self.kittens_rescued += 1

    def is_exhausted(self):
        """ Basically a coin toss. """
        return random.random() < 0.5

    def change_into_super_secret_costume(self):
        print("Beauty, eh?")


class TestStateMachine(unittest.TestCase):

    def setUp(self):
        test_util.print_testname(self._testMethodName)

    def tearDown(self):
        pass

    def test_decorator(self):
        # GIVEN
        machined_hero = StateMachinedHero("batman")
        util.logger.spam(f"name is {machined_hero.name}")
        util.logger.spam(f"state is {machined_hero.state}")

        # WHEN
        machined_hero.wake_up()
        util.logger.spam(f"state is {machined_hero.state}")
        machined_hero.wake_up()
        util.logger.spam(f"state is {machined_hero.state}")

        # THEN
        self.assertEqual(machined_hero.state, "hanging out")

    def test_state_machine_should_support_multiple_instance(self):
        # GIVEN
        batman = StateMachinedHero("batman")
        superman = StateMachinedHero("superman")

        # WHEN
        batman.wake_up()

        # THEN
        self.assertEqual(batman.name, "batman")
        self.assertEqual(superman.name, "superman")

        self.assertEqual(batman.state, "hanging out")
        self.assertEqual(superman.state, "asleep")


class TestTransitions(unittest.TestCase):

    def setUp(self):
        test_util.print_testname(self._testMethodName)

    def tearDown(self):
        pass

    def test_quick_start(self):
        # GIVEN
        batman = StateMachinedHero("Batman")
        util.logger.spam(f"\nstate is {batman.state}")

        # WHEN, THEN
        batman.wake_up()
        util.logger.spam(f"\nstate is {batman.state}")
        self.assertEqual(batman.state, "hanging out")

        batman.nap()
        util.logger.spam(f"\nstate is {batman.state}")
        self.assertEqual(batman.state, "asleep")

        # It works with Machine(ignore_invalid_triggers=True)
        batman.clean_up()
        util.logger.warning(f"\nInvalid trigger ignored state is {batman.state}")
        self.assertEqual(batman.state, "asleep")

        # It needs try except without Machine(ignore_invalid_triggers=True)
        # try:
        #     batman.clean_up()
        # except MachineError as e:
        #     util.logger.error(f"\n{e}")

        batman.wake_up()
        batman.work_out()
        util.logger.spam(f"\nstate is {batman.state}")
        self.assertEqual(batman.state, "hungry")

        util.logger.spam(f"\nkittens_rescued {batman.kittens_rescued}")

        batman.distress_call()
        util.logger.spam(f"\nstate is {batman.state}")
        self.assertEqual(batman.state, "saving the world")

        batman.complete_mission()
        util.logger.spam(f"\nstate is {batman.state}")
        self.assertEqual(batman.state, "sweaty")

        batman.clean_up()
        util.logger.spam(f"\nstate is {batman.state}")
        self.assertTrue(batman.state in ["hanging out", "asleep"])

        util.logger.spam(f"\nkittens_rescued {batman.kittens_rescued}")
        self.assertEqual(batman.kittens_rescued, 1)


if __name__ == '__main__':
    unittest.main()
