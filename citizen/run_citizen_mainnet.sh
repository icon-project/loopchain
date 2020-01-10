#!/bin/bash

CONF_DIR=$PWD/conf

echo "Run citizen with port 7100..."
loopchain -o ${CONF_DIR}/citizen_mainnet.json &

echo "Run iconservice for citizen 7100 start!"
iconservice start -c ${CONF_DIR}/iconservice_mainnet.json &

echo "Run iconrpcserver for citizen 7100 start!"
iconrpcserver start -c ${CONF_DIR}/iconrpcserver_mainnet.json &
