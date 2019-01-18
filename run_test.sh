#!/usr/bin/env bash
python3 -m unittest discover testcase/unittest/ -p "test_*.py" || exit -1
#python3 -m unittest -q testcase.unittest.test_peer.TestPeer.test_query
