#!/bin/sh
# generate python gRPC code by protocol buffer

echo "Generating python grpc code from proto...."
echo "into > " $PWD
cd loopchain
python3 -m grpc.tools.protoc -I'./protos' --python_out='./protos' --grpc_python_out='./protos' './protos/loopchain.proto'
cd ..
echo ""
