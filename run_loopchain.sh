#!/bin/sh

PID_FILE="loopchain.pid"
#SPACE=" "

if [ -f $PID_FILE ]; then
    echo "remove $PID_FILE"
    rm -f $PID_FILE
fi

touch $PID_FILE

echo "Run loopchain for citizen start!"
./loopchain.py citizen -r https://testwallet.icon.foundation -o ./conf/loopchain_conf.json &
echo $! > $PID_FILE

echo "Run iconservice for citizenstart!"
iconservice start -c ./conf/iconservice_conf.json &

echo "Run iconrpcserver for citizen start!"
iconrpcserver start -p 9000 -c conf/iconrpcserver_conf.json &
