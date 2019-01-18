#!/bin/sh

echo "Stop loopchain Processes"

PID_FILE="testnet_citizen.pid"
if [ -f ${PID_FILE} ]; then
    echo "Kill loopchain on testnet process"
    PID=`cat ${PID_FILE}`
    pgrep -P ${PID} | xargs -I ARG kill -9 ARG
    kill ${PID}
    rm -f ${PID_FILE}
fi

echo "Stopping iconservice..."
iconservice stop -c ./conf/testnet/iconservice_conf.json

echo "Stopping iconrpcserver..."
iconrpcserver stop -p 9100 -c ./conf/testnet/iconrpcserver_conf.json
pkill -f gunicorn
