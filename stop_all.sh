#!/bin/sh
echo "Stop loopchain Processes"


echo "Stopping iconservice..."
iconservice stop -c ./conf/iconservice_conf.json


echo "Stopping iconrpcserver..."
iconrpcserver stop -p 9000 -c conf/iconrpcserver_conf.json


PID_FILE="loopchain.pid"
if [ -f ${PID_FILE} ]; then
    echo "Kill All python process"
    PID=`cat ${PID_FILE}`
    pgrep -P ${PID} | xargs -I ARG kill -9 ARG
    kill ${PID}
    rm -f loopchain.pid
fi

pkill -f gunicorn
