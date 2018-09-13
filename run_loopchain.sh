#!/bin/sh

echo "Run loopchain for citizen start!"
loop citizen -r https://testwallet.icon.foundation -o ./conf/loopchain_conf.json &

echo "Run iconservice for citizenstart!"
iconservice start -c ./conf/iconservice_conf.json &

echo "Run iconrpcserver for citizen start!"
iconrpcserver start -p 9000 -c conf/iconrpcserver_conf.json &
