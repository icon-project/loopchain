#!/bin/sh

export REDIRECT_PROTOCOL=https
PID_FILE="mainnet_citizen.pid"

if [ -f ${PID_FILE} ]; then
    echo "remove ${PID_FILE}"
    rm -f ${PID_FILE}
fi

touch ${PID_FILE}

echo "Run loopchain for citizen start!"
./loopchain.py citizen -d -r https://int-ctz.solidwallet.io -o ./conf/mainnet/loopchain_conf.json &
echo $! > $PID_FILE

echo "Run iconservice for citizen start!"
iconservice start -c ./conf/mainnet/iconservice_conf.json &

echo "Run iconrpcserver for citizen start!"
iconrpcserver start -p 9000 -c conf/mainnet/iconrpcserver_conf.json &
