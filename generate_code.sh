#!/bin/sh
# by winDy
# grpc 를 위한 python 코드를 자동으로 생성한다.

echo "Generating python grpc code from proto...."
echo "into > " $PWD
cd loopchain
python3 -m grpc.tools.protoc -I'./protos' --python_out='./protos' --grpc_python_out='./protos' './protos/loopchain.proto'
cd ..
echo ""


echo "Generating test ssl certificate...."

# Getting private ip address using utils.get_private_ip()
ip_address=$(python3 -c 'from loopchain.utils import get_private_ip; print(get_private_ip())')

# Generating ssl.conf from ssl.proto.conf with your ip address
cd resources/ssl_test_cert/
sed "s/{ip_address}/${ip_address}/g" ssl.proto.conf > ssl.conf

# Generating ssl.csr
openssl req -new  -key ssl.key -out ssl.csr -config ssl.conf

# Generating ssl.crt
openssl x509 -req -days 1825 -extensions v3_user -in ssl.csr \
-CA root_ca.crt -CAcreateserial \
-CAkey  root_ca.key \
-out ssl.crt  -extfile ssl.conf

rm ssl.csr
rm ssl.conf
rm root_ca.srl
cd -
echo ""
