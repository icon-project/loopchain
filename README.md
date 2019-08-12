# Loopchain
[![Master Build Status](https://travis-ci.org/icon-project/loopchain.svg?branch=master)](https://travis-ci.org/icon-project/loopchain)
[![Develop Build Status](https://travis-ci.org/icon-project/loopchain.svg?branch=develop)](https://travis-ci.org/icon-project/loopchain)

 Loopchain is a high-performance Blockchain Consensus & Network engine of ICON project.
 
 In order to run a loopchain node, you need to install [ICON Service] 
that runs a smart contract and interacts with loopchain engine, 
and [ICON RPC Server] that processes HTTP requests from clients. 
 
 For details, refer to the guide below.

## Table of Contents

* [Getting Started](#getting-started)
    + [Requirements](#requirements)
    + [Installation](#installation)
    + [TearDown](#teardown)
* [See Also...](#see-also)
    + [Documentation](#documentation)
    + [License](#license)
    
## Getting Started

### Requirements

 Loopchain development and execution requires following environments.

1. Python 3.6.5+ **(recommended 3.7.x)**

    We recommend to create an isolated Python 3 virtual environment with [virtualenv].

    ```bash
    $ virtualenv -p python3 venv
    $ source venv/bin/activate
    ```

    > **_NOTE:_** We will support 3.7.x only in the future. Please upgrade python version to 3.7.x
    
2. **RabbitMQ 3.7+**

    Loopchain requires RabbitMQ.

    For the reliable installation, please visit: [Downloading and Installing RabbitMQ]

3. Other Dependencies

    - **MacOS**
    
        ```bash
        $ brew install automake pkg-config libtool leveldb openssl
        ```

    - **Ubuntu**

        ```bash
        $ sudo apt update
        $ sudo apt install -y make build-essential libssl-dev zlib1g-dev libbz2-dev \
          libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev libncursesw5-dev \
          xz-utils tk-dev libffi-dev liblzma-dev automake libtool lsof
        ```

        **_NOTE_**: If you are using ubuntu 18.04, you need to install additional library `libsecp256k1-dev`

    - **CentOS**

        ```bash
        $ sudo yum update
        $ sudo yum install -y git zlib-devel bzip2 bzip2-devel readline-devel sqlite sqlite-devel openssl-devel \
          xz xz-devel libffi-devel gcc gcc-c++ automake libtool lsof
        ```

### Installation

#### via source code

1. Check all requirements properly installed

    ```bash
    $ make requirements
    ```

    If you don't see any error logs and you have started rabbitmq server, you may move on to next step.

1. Proceed installation

    ```bash
    $ make all
    ```

    This command is for setting up:

    * packages: installs all necessary python packages via `setup.py`.
    * gRPC proto: generates python gRPC code from protocol buffer which is defined in `loopchain.proto`
    * keystore: generates a keystore file.
    
    > **_NOTE_**: Password must be at least 8 characters long including alphabet, number, and special character.  
    > Please be careful not to forget the password since you will need it to run the Citizen Node.

1. Run Citizen

    * [Run Citizen Node on ICON Testnet network]
    * [Run Citizen Node on ICON Mainnet network]

#### via snapcraft (linux only)

1. follow this guide : [install loopchain via snap]

### TearDown

* Clear RabbitMQ processes & pycache & build

    ```bash
    $ make clean
    ```

* Delete log / delete DB

    ```bash
    $ make clean-log clean-db
    ```

> **_NOTE_**: For more command options, `$ make help`


## See Also...

### Documentation

* Please visit [ICON Developers Portal]

### License

* This project follows the [Apache 2.0 License].

<!--Dependencies-->
[ICON Service]: https://github.com/icon-project/icon-service
[ICON RPC Server]: https://github.com/icon-project/icon-rpc-server
[virtualenv]: https://virtualenv.pypa.io/en/stable/
[Downloading and Installing RabbitMQ]: https://www.rabbitmq.com/download.html
[install loopchain via snap]: https://snapcraft.io/loopchain

<!--Relative links-->
[Run Citizen Node on ICON Testnet network]: docs/5.%20run/run_citizen_node.md#run-citizen-node-on-icon-testnet-network
[Run Citizen Node on ICON Mainnet network]: docs/5.%20run/run_citizen_node.md#run-citizen-node-on-icon-mainnet-network

<!--Web pages-->
[ICON Developers Portal]: https://www.icondev.io/
[Apache 2.0 License]: https://www.apache.org/licenses/LICENSE-2.0
