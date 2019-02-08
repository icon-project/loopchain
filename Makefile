requirements:
	@command -v automake > /dev/null || echo "Error: automake is not installed."
	@command -v pkg-config > /dev/null || echo "Error: pkg-config is not installed."
	@command -v libtool > /dev/null || echo "Error: libtool is not installed."
	@command -v openssl > /dev/null || echo "Error: openssl is not installed."
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
	@file="my_keystore.json"; rm -f $${file} > /dev/null; \
	tbears keystore $${file}; \
	cat $${file}
check:
	@echo "Check Python & Gunicorn & RabbitMQ Process..."
	ps -ef | grep loop
	ps -ef | grep gunicorn
	rabbitmqctl list_queues

test:
	@python3 -m unittest discover testcase/unittest/ -p "test_*.py" || exit -1

clean: clean-mq clean-build clean-pyc

clean-mq:
	@echo "Cleaning up RabbitMQ..."
	@rabbitmqctl stop_app
	@rabbitmqctl reset
	@rabbitmqctl start_app

clean-build:
	@rm -rf dist/
	@rm -rf *.egg-info
	@rm -rf .eggs/

clean-pyc:
	@echo "Clear __pycache__"
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +

clean-db:
	@echo "Cleaning up all DB and logs..."
	rm -rf .storage*
	rm -rf log/
