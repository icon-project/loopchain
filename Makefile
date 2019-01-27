requirements:
	@command -v automake || echo "Error: automake is not installed."
	@command -v pkg-config || echo "Error: pkg-config is not installed."
	@command -v libtool || echo "Error: libtool is not installed."
	@command -v openssl || echo "Error: openssl is not installed."
	@if [ "$$(ps -e | grep '[r]abbitmq-server')" = "" ]; then\
		echo "Rabbitmq server is not running locally.";\
	fi

install:
	pip3 install git+https://github.com/icon-project/icon-service.git@master
	pip3 install git+https://github.com/icon-project/icon-commons.git@master
	pip3 install git+https://github.com/icon-project/icon-rpc-server.git@master
	pip3 install tbears
	pip3 install -e .

setup: generate-proto generate-key

generate-proto:
	@echo "Generating python grpc code from proto into > " `pwd`
	python3 -m grpc.tools.protoc -I'./loopchain/protos' --python_out='./loopchain/protos' --grpc_python_out='./loopchain/protos' './loopchain/protos/loopchain.proto'

generate-key:
	@mkdir -p resources/my_pki
	@echo "Generating private key...."
	openssl ecparam -genkey -name secp256k1 | openssl ec -aes-256-cbc -out ./resources/my_pki/my_private.pem
	@echo ""
	@echo "Generating public key from private key...."
	openssl ec -in ./resources/my_pki/my_private.pem -pubout -out ./resources/my_pki/my_public.pem

check:
	@echo "Check Python & Gunicorn & RabbitMQ Process..."
	ps -ef | grep loop
	ps -ef | grep gunicorn
	rabbitmqctl list_queues

test:
	@python3 -m unittest discover testcase/unittest/ -p "test_*.py" || exit -1

clean: clean-mq clean-pyc

clean-mq:
	@echo "Cleaning up RabbitMQ..."
	@rabbitmqctl stop_app
	@rabbitmqctl reset
	@rabbitmqctl start_app

clean-pyc:
	@echo "Clear __pycache__"
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +

clean-db:
	@echo "Cleaning up all DB and logs..."
	rm -rf .storage*
	rm -rf log/
