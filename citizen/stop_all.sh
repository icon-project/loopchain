#!/bin/bash

CONF_DIR=$PWD/conf

if [ "$OSTYPE" == 'darwin'* ]; then
    RABBITMQ_CMD='rabbitmqctl'
elif [ "$OSTYPE" == 'linux-gnu' ]; then
    RABBITMQ_CMD='sudo rabbitmqctl'
fi

echo "Stopping iconservice..."
iconservice stop -c ${CONF_DIR}/iconservice_testnet.json
iconservice stop -c ${CONF_DIR}/iconservice_mainnet.json


echo "Stopping iconrpcserver..."
iconrpcserver stop -p 9000 -c ${CONF_DIR}/iconrpcserver_testnet.json
iconrpcserver stop -p 9000 -c ${CONF_DIR}/iconrpcserver_mainnet.json

echo "Stopping loopchain Processes..."
pgrep -u $(whoami) -f "citizen_(test|main)net.json"
pkill gunicorn
pkill -u $(whoami) -f "citizen_(test|main)net.json"

if [ -n $(which rabbitmqctl) ]; then
    echo "Cleaning up RabbitMQ..."
    ${RABBITMQ_CMD} stop_app
    ${RABBITMQ_CMD} reset
    ${RABBITMQ_CMD} start_app
fi

echo "Check loopchain & Gunicorn"
ps -ef | egrep --color=auto "python|gunicorn"

if [ -n $(which rabbitmqctl) ]; then
    echo "Check RabbitMQ Process..."
    ${RABBITMQ_CMD} list_queues
fi
