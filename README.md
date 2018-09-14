# Loopchain

This is the initial commit for the loopchain.

It will be released in GitHub from now. 
The development of loopchain will also be on Github soon.  

Details will be updated shortly.

## Install Requirements

#### Make Virtual Env for Python 3.6.5 (recommended version, 3.7 is not supported, possible versions are 3.6.x)

 * check your python version

 ```
 $ python3 -V
 ```

 * make virtual env and apply

 ```
 $ virtualenv -p python3 ./venv
 $ source ./venv/bin/activate
 ```

 * check virtual env python version

 ```
 $ python -V
 ```

#### Install third party tools
automake, pkg-config, libtool, leveldb, rabbitmq, openssl

#### Setup RabbitMQ

* increase number of file descriptors

```
$ ulimit -S -n {value: int}
```

- Add the above command to the `rabbitmq-env.conf` file to run the command each time rabbitmq starts.
- You may find this file (/usr/local/etc/rabbitmq/rabbitmq-env.conf).
- Recommended value is 2048 or more. (Local test case only)
- You may need to adjust this value depending on your infrastructure environment.

* start rabbitmq

```
$ brew services start rabbitmq
$ rabbitmqctl list_queues
```

* enable rabbitmq web management

```
$ rabbitmq-plugins enable rabbitmq_management
```

#### Install requirements

```
$ pip3 install git+ssh://git@github.com/icon-project/icon-service.git
$ pip3 install git+ssh://git@github.com/icon-project/icon-commons.git
$ pip3 install git+ssh://git@github.com/icon-project/icon-rpc-server.git
$ pip3 install -r requirements.txt
```

#### Run Test

```
$ ./run_test.sh
```

## Quick Start

#### Generate Key

```
$ mkdir -p resources/my_pki
$ cd resources/my_pki
$ openssl ecparam -genkey -name secp256k1 | openssl ec -aes-256-cbc -out my_private.pem    # generate private key
$ openssl ec -in my_private.pem  -pubout -out my_public.pem                                # generate public key
$ export PW_icon_dex={ENTER_MY_PASSWORD}
$ cd ../../
```

#### Run loopchain as a Citizen Node

```
$ ./run_loopchain.sh
```

#### Stop All

```
# This script does not support all platforms and may need to be modified. (Please refer to the script.)
$ ./stop_all.sh
```

#### Clean Up (delete log / delete DB)

```
$ rm -rf log
$ rm -rf .storage_test
```