#!/bin/sh

export REDIRECT_PROTOCOL=https
PID_FILE="loopchain.pid"

if [ -f $PID_FILE ]; then
    echo "remove $PID_FILE"
    rm -f $PID_FILE
fi

touch $PID_FILE

echo "Run loopchain for citizen start!"
./loopchain.py citizen -r https://cicon.net.solidwallet.io -o ./conf/loopchain_conf.json &
echo $! > $PID_FILE

echo "Run iconservice for citizenstart!"
iconservice start -c ./conf/iconservice_conf.json &

echo "Run iconrpcserver for citizen start!"
iconrpcserver start -p 9000 -c conf/iconrpcserver_conf.json &
