#!/bin/sh

export REDIRECT_PROTOCOL=https
PID_FILE="testnet_citizen.pid"

if [ -f $PID_FILE ]; then
    echo "remove $PID_FILE"
    rm -f $PID_FILE
fi

touch $PID_FILE

echo "Run loopchain for citizen start!"
./loopchain.py citizen -r https://test-ctz.solidwallet.io -o ./conf/testnet/loopchain_conf.json &
echo $! > $PID_FILE

echo "Run iconservice for citizen start!"
iconservice start -c ./conf/testnet/iconservice_conf.json &

echo "Run iconrpcserver for citizen start!"
iconrpcserver start -p 9100 -c conf/testnet/iconrpcserver_conf.json &
