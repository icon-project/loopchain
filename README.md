# Loopchain

[![loopchain](https://img.shields.io/badge/ICON-Consensus-blue?logoColor=white&logo=icon&labelColor=31B8BB)](https://shields.io)
[![loopchain](https://snapcraft.io/loopchain/badge.svg)](https://snapcraft.io/loopchain)
[![Citizen Sync](https://github.com/icon-project/loopchain/workflows/Citizen%20Sync/badge.svg)](#)
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/icon-project/loopchain.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/icon-project/loopchain/context:python)

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

1. **Python 3.7.x**

    We recommend to create an isolated Python 3 virtual environment with [virtualenv].

    ```bash
    $ virtualenv -p python3 venv
    $ source venv/bin/activate
    ```

    > **_NOTE:_** Now we support 3.7.x only. Please upgrade python version to 3.7.x

1. **RabbitMQ 3.7+**

    Loopchain requires RabbitMQ.

    For the reliable installation, please visit: [Downloading and Installing RabbitMQ]

1. **Reward Calculator**

    [Reward calculator] is a daemon which calculates I-Score of ICONists to support IISS.

    Please visit [Reward calculator] github repository to install it.

1. Other Dependencies

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
[Reward Calculator]: https://github.com/icon-project/rewardcalculator
[virtualenv]: https://virtualenv.pypa.io/en/stable/
[Downloading and Installing RabbitMQ]: https://www.rabbitmq.com/download.html
[install loopchain via snap]: citizen/quick_start_snap.md

<!--Relative links-->
[Run Citizen Node on ICON Testnet network]: docs/5.%20run/run_citizen_node.md#run-citizen-node-on-icon-testnet-network
[Run Citizen Node on ICON Mainnet network]: docs/5.%20run/run_citizen_node.md#run-citizen-node-on-icon-mainnet-network

<!--Web pages-->
[ICON Developers Portal]: https://www.icondev.io/
[Apache 2.0 License]: https://www.apache.org/licenses/LICENSE-2.0
