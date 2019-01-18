# Loopchain

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

#### Setting environments (for local OS X)

* install Xcode command tool
* install brew (if it's not installed)

```bash
$ /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
```

* Install third party tools

```bash
$ brew install automake pkg-config libtool leveldb rabbitmq openssl
```

#### Setup RabbitMQ

* increase number of RabbitMQ file descriptors

```
ulimit -S -n {value: int}
```

- Add the above command to the `rabbitmq-env.conf` file to run the command each time rabbitmq starts.
- You may find this file (/usr/local/etc/rabbitmq/rabbitmq-env.conf).
- Recommended value is 2048 or more. (Local test case only)
- You may need to adjust this value depending on your infrastructure environment.

* start rabbitmq

```bash
$ brew services start rabbitmq
$ rabbitmqctl list_queues
```

* enable rabbitmq web management

```bash
$ rabbitmq-plugins enable rabbitmq_management
```

#### Install requirements

If you have generated ssh key for github, you can install with below commands.

```bash
$ pip3 install git+ssh://git@github.com/icon-project/icon-service.git@master
$ pip3 install git+ssh://git@github.com/icon-project/icon-commons.git@master
$ pip3 install git+ssh://git@github.com/icon-project/icon-rpc-server.git@master
$ pip3 install -r requirements.txt
```

Also, you can install with below commands too.

```bash
$ pip3 install git+https://github.com/icon-project/icon-service.git@master
$ pip3 install git+https://github.com/icon-project/icon-commons.git@master
$ pip3 install git+https://github.com/icon-project/icon-rpc-server.git@master
$ pip3 install -r requirements.txt
```

#### generate gRPC code

```bash
$ ./generate_code.sh
```

#### Run Unittest

```bash
$ ./run_test.sh
```

## Quick Start

#### Generate Key

```bash
$ mkdir -p resources/my_pki
$ openssl ecparam -genkey -name secp256k1 | openssl ec -aes-256-cbc -out ./resources/my_pki/my_private.pem    # generate private key
$ openssl ec -in ./resources/my_pki/my_private.pem  -pubout -out ./resources/my_pki/my_public.pem             # generate public key
$ export PW_icon_dex={ENTER_MY_PASSWORD}
```

### Run Citizen Node on ICON Testnet network
This script will enable ICON citizen node on Testnet network, running on port 9100.
Once it's connected to the network, it will start to sync all the blocks on the ICON testnet network.
As we do not support fast sync mode for now, it may take some time to sync all the blocks. The feature will be implemented soon.

```bash
$ ./run_testnet_citizen.sh
```

#### Test through command line interface for ICON

* Install t-bears

T-Bears provides the command line interface to interact with the ICON network. It implements all the JSON-RPC v3 APIs.
For a detailed usage guideline, please see T-Bears tutorial.

```bash
(venv) $ pip3 install tbears
```

* Check block data

  * get lastblock
  ```bash
  $ tbears lastblock -u http://127.0.0.1:9100/api/v3
  ```

  * get totalsupply
  ```bash
  $ tbears totalsupply -u http://127.0.0.1:9100/api/v3
  ```

* Stop the testnet citizen node

```bash
$ ./stop_testnet_citizen.sh
```

### Run Citizen Node on ICON Mainnet network
This script will enable ICON citizen node on Mainnet network, running on port 9000.

```bash
$ ./run_mainnet_citizen.sh
```


ICON Testnet Tracker()

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
