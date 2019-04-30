# Loopchain

 Loopchain is a high-performance Blockchain Consensus & Network engine of ICON project.

 In order to run a loopchain node, you need to install [ICON Service](https://github.com/icon-project/icon-service) that runs a smart contract and interacts with loopchain engine, and [ICON RPC Server](https://github.com/icon-project/icon-rpc-server) that processes HTTP requests from clients. For details, refer to the guide below.

## Installation

### Requirements

Loopchain development and execution requires following environments.

* OS: MacOS, Linux
  * Windows are not supported yet.

* Python

  * Python 3.6.5+ or 3.7.x (recommended version)

    **We will support 3.7.x only in future. Please upgrade python version to 3.7.x.**

    Optional) We recommend to create an isolated Python 3 virtual environment with [virtualenv](https://virtualenv.pypa.io/en/stable/).

    ```bash
    $ virtualenv -p python3 venv
    $ source venv/bin/activate
    ```

* Third party tools

    ```
    automake pkg-config libtool leveldb rabbitmq openssl
    ```

    If you're using package manager, you can install all of them through your package manager.

    MacOS, for example)
    
    ```bash
    $ brew install automake pkg-config libtool leveldb rabbitmq openssl
    $ brew services start rabbitmq
    ```

* Check all requirements are installed and started properly

    ```bash
    $ make requirements
    ```

    If you don't see any error logs and you have started rabbitmq server, you may move on to next step.

### Install necessary packages & Setup

This command is for setting up:
* pip install all necessary packages.
* generates python gRPC code from protocol buffer which is defined in `loopchain.proto`
* generates a keystore file. **Please be careful not to forget the password since you will need it to run Citizen Node later.**

```bash
$ make all

...
Generating python grpc code from proto into >  /Users/jiyun/Desktop/happycoding/workspace/theloop/LoopChain
python3 -m grpc.tools.protoc -I'./loopchain/protos' --python_out='./loopchain/protos' --grpc_python_out='./loopchain/protos' './loopchain/protos/loopchain.proto'
Input your keystore password:  # Password must be at least 8 characters long including alphabet, number, and special character.
```

> For more command options, you can check here:

```bash
$ make help
```

## Run Citizen Node on ICON network

* [Run Citizen Node on ICON Testnet network](docs/5.%20run/run_citizen_node.md#run-citizen-node-on-icon-testnet-network)
* [Run Citizen Node on ICON Mainnet network](docs/5.%20run/run_citizen_node.md#run-citizen-node-on-icon-mainnet-network)


#### Clean Up

* clear rabbitMQ processes & pycache & build

```bash
$ make clean
```

* delete log / delete DB

```bash
$ make clean-db
```

## License

This project follows the Apache 2.0 License. Please refer to [LICENSE](https://www.apache.org/licenses/LICENSE-2.0) for details.
