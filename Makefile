UNAME := $(shell uname)
USER_MAKEFILE := user.mk

PIP_INSTALL := pip3 install
ifeq ($(wildcard $(USER_MAKEFILE)),)
	INSTALL_REQUIRES := requires
	PIP_INSTALL_CMD := $(PIP_INSTALL) -e .
	PIP_INSTALL_DEVELOP_CMD := $(PIP_INSTALL_CMD)[tests]
else
	include $(USER_MAKEFILE)
endif
PIP_INSTALL += -U

ifeq ($(UNAME), Darwin)
	RABBITMQ_CMD := rabbitmqctl
else ifeq ($(UNAME), Linux)
	RABBITMQ_CMD := sudo rabbitmqctl
endif

help:
	@awk '/^#/{c=substr($$0,3);next}c&&/^[[:alpha:]][-_[:alnum:]]+:/{print substr($$1,1,index($$1,":")),c}1{c=0}' $(MAKEFILE_LIST) | column -s: -t

# Check all requirements are installed and started properly.
requirements:
	@command -v automake > /dev/null || echo "Error: automake is not installed."
	@command -v pkg-config > /dev/null || echo "Error: pkg-config is not installed."
	@command -v libtool > /dev/null || echo "Error: libtool is not installed."
	@command -v openssl > /dev/null || echo "Error: openssl is not installed."
	@if [ "$$(ps -e | grep '[r]abbitmq-server')" = "" ]; then\
		echo "Rabbitmq server is not running locally.";\
	fi
	@echo "The check for required packages installation is completed."

# pip install packages & generate all
all: install generate-key

# pip install packages
requires:
	$(PIP_INSTALL) git+https://github.com/icon-project/icon-service.git@master
	$(PIP_INSTALL) git+https://github.com/icon-project/icon-commons.git@master
	$(PIP_INSTALL) git+https://github.com/icon-project/icon-rpc-server.git@master
	$(PIP_INSTALL) tbears

install: $(INSTALL_REQUIRES)
	$(PIP_INSTALL_CMD)

# pip install packages
requires-dev:
	$(PIP_INSTALL) git+https://github.com/icon-project/icon-service.git@loopchain_iiss
	$(PIP_INSTALL) git+https://github.com/icon-project/icon-commons.git@master
	$(PIP_INSTALL) git+https://github.com/icon-project/icon-rpc-server.git@develop
	$(PIP_INSTALL) tbears

develop: requires-dev
	$(PIP_INSTALL_DEVELOP_CMD)

# Generate python gRPC proto
generate-proto:
	@echo "Generating python grpc code from proto into > " `pwd`
	python3 -m grpc_tools.protoc -I'./loopchain/protos' \
		--python_out='./loopchain/protos' \
		--grpc_python_out='./loopchain/protos' \
		'./loopchain/protos/loopchain.proto'

# Generate a key
generate-key:
	@file="my_keystore.json"; rm -f $${file} > /dev/null; \
	tbears keystore $${file}; \
	cat $${file}

# Check loopchain & gunicorn & rabbitmq processes
check:
	@echo "Check loopchain & Gunicorn & RabbitMQ Process..."
	ps -ef | egrep --color=auto "loop|gunicorn"
	@$(RABBITMQ_CMD) list_queues

# Run unittest
test:
	@python3 -m unittest discover testcase/unittest/ -p "test_*.py" || exit -1

# Clean all - clean-process clean-mq clean-pyc clean-db clean-log
clean: clean-process clean-mq clean-pyc clean-db clean-log clean-test check

clean-process:
	@pkill -f loop || true
	@pkill -f gunicorn || true

clean-mq:
	@echo "Cleaning up RabbitMQ..."
	@$(RABBITMQ_CMD) stop_app
	@$(RABBITMQ_CMD) reset
	@$(RABBITMQ_CMD) start_app

clean-build:
	@rm -rf build/
	@rm -rf dist/
	@rm -rf *.egg-info
	@rm -rf .eggs/

clean-pyc:
	@echo "Clear __pycache__"
	@find . -name '*.pyc' -exec rm -f {} +
	@find . -name '*.pyo' -exec rm -f {} +
	@find . -name '*~' -exec rm -f {} +

clean-db:
	@echo "Cleaning up all DB..."
	@rm -rf .storage*

clean-log:
	@echo "Cleaning up logs..."
	@rm -rf log/

clean-test:
	@echo "Cleaning up test related cache..."
	@rm -rf .hypothesis/
	@rm -rf .xprocess/
	@rm -rf .pytest_cache/

# build
build: clean-build
	@if [ "$$(python -c 'import sys; print(sys.version_info[0])')" != 3 ]; then\
		@echo "The script should be run on python3.";\
		exit -1;\
	fi

	@if ! python -c 'import wheel' &> /dev/null; then \
		pip install wheel; \
	fi

	@if ! python -c 'import grpc_tools' &> /dev/null; then \
		pip install grpcio==1.20.1; \
		pip install grpcio-tools==1.20.1; \
		pip install protobuf==3.7.0; \
	fi

	python3 setup.py bdist_wheel
