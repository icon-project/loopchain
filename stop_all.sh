#!/bin/sh
echo "Stop loopchain Processes"


echo "Stopping iconservice..."
iconservice stop -c ./conf/iconservice_conf.json


echo "Stopping iconrpcserver..."
iconrpcserver stop -p 9000 -c conf/iconrpcserver_conf.json


echo "Kill All python process"

pgrep -f python | xargs kill -9
pkill -f gunicorn
