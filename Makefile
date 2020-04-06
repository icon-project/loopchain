UNAME := $(shell uname)
USER_MAKEFILE := user.mk

PIP_INSTALL := pip3 install
ifeq ($(wildcard $(USER_MAKEFILE)),)
	INSTALL_REQUIRES := requires
	INSTALL_DEVELOP_REQUIRES := requires-dev
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

CLEAN_TARGETS := clean-process clean-mq clean-pyc clean-db clean-log clean-test
TEST_CMD := python -m pytest -rsxX

help:
	@awk '/^#/{c=substr($$0,3);next}c&&/^[[:alpha:]][-_[:alnum:]]+:/{print substr($$1,1,index($$1,":")),c}1{c=0}'\
	 $(MAKEFILE_LIST) | column -s: -t

## Check all requirements are installed and started properly.
requirements:
	@command -v automake > /dev/null || echo "Error: automake is not installed."
	@command -v pkg-config > /dev/null || echo "Error: pkg-config is not installed."
	@command -v libtool > /dev/null || dpkg -l libtool > /dev/null || echo "Error: libtool is not installed."
	@command -v openssl > /dev/null || echo "Error: openssl is not installed."
	@if [ "$$(ps -e | grep '[r]abbitmq-server')" = "" ]; then\
		echo "Rabbitmq server is not running locally.";\
	fi
	@echo "The check for required packages installation is completed."

## pip install packages & generate all
all: install generate-key

requires:
	$(PIP_INSTALL) iconservice==1.6.1
	$(PIP_INSTALL) iconcommons==1.1.2
	$(PIP_INSTALL) iconrpcserver==1.4.9
	$(PIP_INSTALL) tbears

## pip install packages
install: $(INSTALL_REQUIRES)
	$(PIP_INSTALL_CMD)

requires-dev:
	$(PIP_INSTALL) git+https://github.com/icon-project/icon-service.git@develop
	$(PIP_INSTALL) git+https://github.com/icon-project/icon-commons.git@master
	$(PIP_INSTALL) git+https://github.com/icon-project/icon-rpc-server.git@develop

## pip install packages for develop
develop: $(INSTALL_DEVELOP_REQUIRES)
	$(PIP_INSTALL_DEVELOP_CMD)

## Generate python gRPC proto
generate-proto:
	@echo "Generating python grpc code from proto"
	@python3 setup.py build_proto_modules

## Generate a key
generate-key:
	@file="my_keystore.json"; $(RM) $${file} > /dev/null; \
	tbears keystore $${file}; \
	cat $${file}

## Check loopchain & gunicorn & rabbitmq processes
check:
	@echo "Check loopchain & Gunicorn & RabbitMQ Process..."
	ps -ef | egrep --color=auto "loop|gunicorn"
	@$(RABBITMQ_CMD) list_queues

## Run unittest
test: unit-test integration-test

unit-test:
	@echo "Start unit test..."
	$(TEST_CMD) testcase/unittest --benchmark-disable || exit -1

integration-test:
	@echo "Start integration test..."
	$(TEST_CMD) testcase/integration || exit -1

## Clean all - clean-process clean-mq clean-pyc clean-db clean-log clean-test
clean: $(CLEAN_TARGETS) check

clean-process:
	@pkill -f loop || true
	@pkill -f gunicorn || true

clean-mq:
	@echo "Cleaning up RabbitMQ..."
	@$(RABBITMQ_CMD) stop_app
	@$(RABBITMQ_CMD) reset
	@$(RABBITMQ_CMD) start_app

clean-build:
	@$(RM) -r build/ dist/
	@$(RM) -r .eggs/ eggs/ *.egg-info/

clean-pyc:
	@echo "Clear __pycache__"
	@find . -name '*.pyc' -exec $(RM) {} +
	@find . -name '*.pyo' -exec $(RM) {} +
	@find . -name '*~' -exec $(RM) {} +

clean-db:
	@echo "Cleaning up all DB..."
	@$(RM) -r .storage*

clean-log:
	@echo "Cleaning up logs..."
	@$(RM) -r log/

clean-test:
	@echo "Cleaning up test related cache..."
	@$(RM) -r .hypothesis/ .xprocess/ .pytest_cache/

clean-proto:
	@find . -name 'loopchain_pb*.py' -exec $(RM) {} +

## build python wheel
build: clean-build clean-proto
	@if [ "$$(python -c 'import sys; print(sys.version_info[0])')" != 3 ]; then\
		@echo "The script should be run on python3.";\
		exit -1;\
	fi

	@if ! python -c 'import wheel' &> /dev/null; then \
		pip install wheel; \
	fi

	python3 setup.py bdist_wheel
