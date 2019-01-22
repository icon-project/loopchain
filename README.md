# Loopchain

 Loopchain is a high-performance Blockchain Consensus & Network engine of ICON project.

 In order to run a loopchain node, you need to install [ICON Service](https://github.com/icon-project/icon-service) that runs a smart contract and interacts with loopchain engine, and [ICON RPC Server](https://github.com/icon-project/icon-rpc-server) that processes HTTP requests from clients. For details, refer to the guide below.

## Installation

### Requirements

Loopchain development and execution requires following environments.

* OS: MacOS, Linux
  * Windows are not supported yet.

* Python
  * Make Virtual Env for Python 3.6.5+ (recommended version, 3.7 is not supported)
  * check your python version

  ```bash
  $ python3 -V
  ```

  > If you'd like to easily manage your python version by each projects, we highly recommend to use **pyenv**.
   * Install **pyenv**
   ```
   $ curl -L https://github.com/pyenv/pyenv-installer/raw/master/bin/pyenv-installer | bash
   ```

   * Append the following commands to `~/.bash_profile`.
   ```
   export PATH="/home/centos/.pyenv/bin:$PATH"
   eval "$(pyenv init -)"
   eval "$(pyenv virtualenv-init -)"
   ```
   * Apply for the profile

   ```
   $ source ~/.bash_profile
   ```
   * Install **python 3.6.5**

   ```
   $ pyenv install 3.6.5
   $ pyenv shell 3.6.5
   ```

   * make virtual env and apply

   ```
   $ virtualenv -p python3 ./venv
   $ source ./venv/bin/activate
   ```

### Setup on MacOS

* install Xcode command tool
* install brew

  ```bash
  (venv) $ /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
  ```

* Install third party tools

  ```bash
  (venv) $ brew install automake pkg-config libtool leveldb rabbitmq openssl
  ```

* Setup RabbitMQ

  * increase number of RabbitMQ file descriptors

  > Add the below command to the `rabbitmq-env.conf` file to run the command each time rabbitmq starts.
    ```
    ulimit -S -n {value: int}
    ```
  > You may find this file (/usr/local/etc/rabbitmq/rabbitmq-env.conf).
  > Recommended value is 2048 or more. (Local test case only)
  > You may need to adjust this value depending on your infrastructure environment.

  * start rabbitmq

  ```bash
  (venv) $ brew services start rabbitmq
  (venv) $ rabbitmqctl list_queues
  ```

  * enable rabbitmq web management

  ```bash
  (venv) $ rabbitmq-plugins enable rabbitmq_management
  ```

#### Install requirements

If you have generated ssh key for github, you can install with below commands.
All libraries are recommended to install the master version of github.

```bash
(venv) $ pip3 install git+ssh://git@github.com/icon-project/icon-service.git@master
(venv) $ pip3 install git+ssh://git@github.com/icon-project/icon-commons.git@master
(venv) $ pip3 install git+ssh://git@github.com/icon-project/icon-rpc-server.git@master
(venv) $ pip3 install -r requirements.txt
```

Also, you can install with below commands as well.

```bash
(venv) $ pip3 install git+https://github.com/icon-project/icon-service.git@master
(venv) $ pip3 install git+https://github.com/icon-project/icon-commons.git@master
(venv) $ pip3 install git+https://github.com/icon-project/icon-rpc-server.git@master
(venv) $ pip3 install -r requirements.txt
```

#### generate gRPC code
This script generates python gRPC code from protocol buffer which is defined in `loopchain.proto`.

```bash
(venv) $ ./generate_code.sh
```

#### Run Unittest
After installation, run the unittest by following command line in order to check whether it operates well or not.

```bash
(venv) $ ./run_test.sh
```

## Quick Start

* [Run Citizen Node on ICON Testnet network](#run-citizen-node-on-icon-testnet-network)
* [Run Citizen Node on ICON Mainnet network](#run-citizen-node-on-icon-mainnet-network)

### Run Citizen Node on ICON Testnet network

#### Generate Key

```bash
(venv) $ mkdir -p resources/my_pki
(venv) $ openssl ecparam -genkey -name secp256k1 | openssl ec -aes-256-cbc -out ./resources/my_pki/my_private.pem    # generate private key
(venv) $ openssl ec -in ./resources/my_pki/my_private.pem  -pubout -out ./resources/my_pki/my_public.pem             # generate public key
(venv) $ export PW_icon_dex={ENTER_MY_PASSWORD}
(venv) $ export REDIRECT_PROTOCOL=https
```

This script will enable ICON citizen node on Testnet network, running on port **9000**.
Once it's connected to the network, it will start to sync all the blocks on the ICON testnet network.

```bash
(venv) $ ./loop citizen -r testnet
```

If you want to browse and search the blocks and transactions in ICON Testnet, please go to [ICON testnet tracker](https://trackerdev.icon.foundation).

#### Test through command line interface for ICON

T-Bears is a suite of development tools for SCORE and provides the command line interface to interact with the ICON network including all the JSON-RPC v3 APIs.
For a detailed usage guideline, please refer to [T-Bears tutorial](https://github.com/icon-project/t-bears).

* Install t-bears

```bash
(venv) $ pip3 install tbears
```

##### Test jsonRPC APIs
In v3, parameters in all api request params require the string '0x' at the front.

* get lastblock

This method returns the last block the Citizen node has currently synced.

```bash
usage: tbears lastblock [-h] [-u URI] [-c CONFIG]

// Example
(venv) $ tbears lastblock  // Example (default uri: http://localhost:9000/api/v3)

// result
block info : {
    "jsonrpc": "2.0",
    "result": {
        "version": "0.1a",
        "prev_block_hash": "c5dae2634737e28ff4a1987abe1362890f8a6aaea3e7c0086f5e5fe5300361eb",
        "merkle_tree_root_hash": "a0c897c5b78860e8500019a3a0788e0498aeec20f3e8e57cc22d9c5096e6ab84",
        "time_stamp": 1537335737897461,
        "confirmed_transaction_list": [
            {
                "stepLimit": "0x1e8480",
                "signature": "k+F7dxstj1mXr7AL2hGo8RMgAEW0fc8AEhXMPiZOzBgvZYvcIkyVrUdoTnoTMJK55420+36ZdOBoo/tiM1AGZgE=",
                "nid": "0x2",
                "from": "hx8f1796338f819e4e0276e7d449227a3bfb7ea2a6",
                "to": "cx3ae5c047638df3e3b02120c913dda852ff84d297",
                "version": "0x3",
                "value": "0xde0b6b3a7640000",
                "nonce": "0x1",
                "timestamp": "0x57632de7fb4f8",
                "txHash": "0xa0c897c5b78860e8500019a3a0788e0498aeec20f3e8e57cc22d9c5096e6ab84"
            }
        ],
        "block_hash": "da8abc0c9bad1d5b868c17b4a3e575ad7b2b8430880e233490fad1811a12277c",
        "height": 30000,
        "peer_id": "hx98cd0d78e8936b633210b04a6ce10eab655c0881",
        "signature": "J4PrnX0jG5sXcdf1bscPvlZPCioDv+pezm1WkEFlOqg8ZHTNZT9LSkCjZFLVbKfObkYRmHDPmGfLgBTPMvZV3wE="
    },
    "id": 1
}
```

* get blockbyheight

```bash
usage: tbears blockbyheight [-h] [-u URI] [-c CONFIG] height

// Example
(venv) $ tbears blockbyheight 0x1

// result
block info : {
  "jsonrpc": "2.0",
  "result": {
      "version": "0.1a",
      "prev_block_hash": "885b8021826f7e741be7f53bb95b48221e9ab263f377e997b2e47a7b8f4a2a8b",
      "merkle_tree_root_hash": "cb3a60b8cba5c7647fa7d2eb351be0723b8a733c41c6bfa0e9f4e6f5b89378e7",
      "time_stamp": 1519289604305467,
      "confirmed_transaction_list": [
          {
              "from": "hx5a05b58a25a1e5ea0f1d5715e1f655dffc1fb30a",
              "to": "hx7bcf759a16661dbb9356318af31dc6d4803fc969",
              "value": "0x845951614014880000000",
              "fee": "0x2386f26fc10000",
              "timestamp": "1519289604008199",
              "tx_hash": "cb3a60b8cba5c7647fa7d2eb351be0723b8a733c41c6bfa0e9f4e6f5b89378e7",
              "signature": "HIjTnNCwHwTiSs7Ucj+oXsyc0ZzDDz9jIKWoQouifEYOCkaAWz8swKet/neGBBckLm6GujqDajWZ290Hoq/ROwE=",
              "method": "icx_sendTransaction"
          }
      ],
      "block_hash": "d5629fe006104df557570ce2613c8df1901d8f6f322b9f251645c201fa1d1e9e",
      "height": 1,
      "peer_id": "hx1fe2dfae9a5439bb1d4e193a3b7c6e5df6c6650e",
      "signature": "lGQu4IdK/ZPeCB4e2IJc8s0l38uh30OmH/xSXE7+STpMJaphHbFJYtl7U/Y7bgWhJtQri+GJsp25PyNRzioabAE="
  },
  "id": 1
```

* get blockbyhash

```bash
usage: tbears blockbyhash [-h] [-u URI] [-c CONFIG] hash

// Example

(venv) $ tbears blockbyhash 0xce00facd0ac3832e1e6e623d8f4b9344782da881e55abb48d1494fde9e465f78

// Result is same as above.
```

* get totalsupply

```bash
usage: tbears totalsupply [-h] [-u URI] [-c CONFIG]

// Example
(venv) $ tbears totalsupply

// Result
Total supply of ICX in hex: 0x2961fff8ca4a62327800000
Total supply of ICX in decimal: 800460000000000000000000000
```

* Create a Keystore

Create a keystore file in the given path. Generate a private and public key pair using secp256k1 library.

```bash
usage: tbears keystore [-h] [-p PASSWORD] path

// Example
(venv) $ tbears keystore ./my_keystore.json

input your keystore password: (You have to initialize your keystore password)

Made keystore file successfully
```

It will create new keystore file like this:

```json
// my_keystore.json
{
  "address": "hx63499c4efc26c9370f6d68132c116d180d441266",  // address for your account
  "crypto": {
    "cipher": "aes-128-ctr",
    "cipherparams": {
      "iv": "1a3b55deff9809c702e5da6265efe759",
    },
    "ciphertext": "42e4e768cfdedc54446efc7c0b7726326394d4c0b753ef76827ef1bdd3a7d5c9",
    "kdf": "scrypt",
    "kdfparams": {
      "dklen": 32,
      "n": 16384,
      "r": 1,
      "p": 8,
      "salt": "fdaff79a618e562a17224dd6c2072025",
    },
    "mac": "400cbabc7fcff73ac5a28f64a0d36a5007b1a40e6ac2fe8fd2b771d89fe43385",
  },
  "id": "15240a99-1c08-4b44-8cdd-5b9ebe71530f",
  "version": 3,
  "coinType": "icx"
}
```

> For there's no balance at that address, you need to request some testnet icx to your address. The instruction and the link to request testnet icx will be updated soon.

* get balance

```bash
usage: tbears balance [-h] [-u URI] [-c CONFIG] address

// Example
(venv) $ tbears balance hx63499c4efc26c9370f6d68132c116d180d441266

// Result
balance in hex: 0xde0b6b3a7640000
balance in decimal: 1000000000000000000
```

* Send transaction

Now that you have received a sufficient amount of icx, you can use it to send transactions.

```
usage: tbears sendtx [-h] [-u URI] [-k KEYSTORE] [-c CONFIG] json_file

Request icx_sendTransaction with the specified json file and keystore file. If
keystore file is not given, tbears sends request as it is in the json file.

positional arguments:
  json_file             File path containing icx_sendTransaction content

optional arguments:
  -h, --help            show this help message and exit
  -u URI, --node-uri URI
                        URI of node (default: http://127.0.0.1:9000/api/v3)
  -k KEYSTORE, --key-store KEYSTORE
                        Keystore file path. Used to generate "from" address and
                        transaction signature
  -c CONFIG, --config CONFIG
                        Configuration file path. This file defines the default
                        value for the "uri" (default: ./tbears_cli_config.json)
```

We provide the minimal settings for the simple coin transfer in the `sendtx_testnet.json` file.
The address to which icx is sent(`to`) is the address the ICON developers usually use when testing. You can change the address and the value if you want.
```json
// sendtx_testnet.json

{
  "jsonrpc": "2.0",
  "method": "icx_sendTransaction",
  "params": {
    "version": "0x3",  // transaction version
    "to": "hx670e692ffd3d5587c36c3a9d8442f6d2a8fcc795",  // default address for testing
    "value": "0xde0b6b3a7640000",  // 1 ICX
    "stepLimit": "0x3000000",
    "nid": "0x2"  // network id for testnet
  },
  "id": 1
}
```

Example

```bash
(venv) $ tbears sendtx -k my_keystore.json send.json

input your keystore password:

Send transaction request successfully.
transaction hash: 0xc8a3e3f77f21f8f1177d829cbc4c0ded6fd064cc8e42ef309dacff5c0a952289
```

  For the details, please go to [Command-line Interfaces(CLIs)](https://github.com/icon-project/t-bears#command-line-interfacesclis) chapter in t-bears repository.

### Run Citizen Node on ICON Mainnet network

#### Generate Key

```bash
(venv) $ mkdir -p resources/my_pki
(venv) $ openssl ecparam -genkey -name secp256k1 | openssl ec -aes-256-cbc -out ./resources/my_pki/my_private.pem    # generate private key
(venv) $ openssl ec -in ./resources/my_pki/my_private.pem  -pubout -out ./resources/my_pki/my_public.pem             # generate public key
(venv) $ export PW_icon_dex={ENTER_MY_PASSWORD}
(venv) $ export REDIRECT_PROTOCOL=https
```

This script will enable ICON citizen node on Mainnet network, running on port **9100**.
Once it's connected to the network, it will start to sync all the blocks on the ICON mainnet network.

```bash
(venv) $ ./loop citizen -r mainnet
```

If you want to browse and search the blocks and transactions in ICON Mainnet, please go to [ICON tracker](https://tracker.icon.foundation).

#### Test through command line interface for ICON

Since the mainnet citizen runs on port 9100, you need `-u http://127.0.0.1:9100/api/v3` for all command options in tbears that requires uri option.

##### Test jsonRPC APIs
In v3, parameters in all api request params require the string '0x' at the front.

* get lastblock

This method returns the last block the Citizen node has currently synced.

```bash
usage: tbears lastblock [-h] [-u URI] [-c CONFIG]

// Example
(venv) $ tbears lastblock -u http://127.0.0.1:9100/api/v3 // Example (default uri: http://localhost:9000/api/v3)

// result
block info : {
    "jsonrpc": "2.0",
    "result": {
        "version": "0.1a",
        "prev_block_hash": "c5dae2634737e28ff4a1987abe1362890f8a6aaea3e7c0086f5e5fe5300361eb",
        "merkle_tree_root_hash": "a0c897c5b78860e8500019a3a0788e0498aeec20f3e8e57cc22d9c5096e6ab84",
        "time_stamp": 1537335737897461,
        "confirmed_transaction_list": [
            {
                "stepLimit": "0x1e8480",
                "signature": "k+F7dxstj1mXr7AL2hGo8RMgAEW0fc8AEhXMPiZOzBgvZYvcIkyVrUdoTnoTMJK55420+36ZdOBoo/tiM1AGZgE=",
                "nid": "0x2",
                "from": "hx8f1796338f819e4e0276e7d449227a3bfb7ea2a6",
                "to": "cx3ae5c047638df3e3b02120c913dda852ff84d297",
                "version": "0x3",
                "value": "0xde0b6b3a7640000",
                "nonce": "0x1",
                "timestamp": "0x57632de7fb4f8",
                "txHash": "0xa0c897c5b78860e8500019a3a0788e0498aeec20f3e8e57cc22d9c5096e6ab84"
            }
        ],
        "block_hash": "da8abc0c9bad1d5b868c17b4a3e575ad7b2b8430880e233490fad1811a12277c",
        "height": 30000,
        "peer_id": "hx98cd0d78e8936b633210b04a6ce10eab655c0881",
        "signature": "J4PrnX0jG5sXcdf1bscPvlZPCioDv+pezm1WkEFlOqg8ZHTNZT9LSkCjZFLVbKfObkYRmHDPmGfLgBTPMvZV3wE="
    },
    "id": 1
}
```

* get blockbyheight

```bash
usage: tbears blockbyheight [-h] [-u URI] [-c CONFIG] height

// Example
(venv) $ tbears blockbyheight -u http://127.0.0.1:9100/api/v3 0x1

// result
block info : {
  "jsonrpc": "2.0",
  "result": {
      "version": "0.1a",
      "prev_block_hash": "885b8021826f7e741be7f53bb95b48221e9ab263f377e997b2e47a7b8f4a2a8b",
      "merkle_tree_root_hash": "cb3a60b8cba5c7647fa7d2eb351be0723b8a733c41c6bfa0e9f4e6f5b89378e7",
      "time_stamp": 1519289604305467,
      "confirmed_transaction_list": [
          {
              "from": "hx5a05b58a25a1e5ea0f1d5715e1f655dffc1fb30a",
              "to": "hx7bcf759a16661dbb9356318af31dc6d4803fc969",
              "value": "0x845951614014880000000",
              "fee": "0x2386f26fc10000",
              "timestamp": "1519289604008199",
              "tx_hash": "cb3a60b8cba5c7647fa7d2eb351be0723b8a733c41c6bfa0e9f4e6f5b89378e7",
              "signature": "HIjTnNCwHwTiSs7Ucj+oXsyc0ZzDDz9jIKWoQouifEYOCkaAWz8swKet/neGBBckLm6GujqDajWZ290Hoq/ROwE=",
              "method": "icx_sendTransaction"
          }
      ],
      "block_hash": "d5629fe006104df557570ce2613c8df1901d8f6f322b9f251645c201fa1d1e9e",
      "height": 1,
      "peer_id": "hx1fe2dfae9a5439bb1d4e193a3b7c6e5df6c6650e",
      "signature": "lGQu4IdK/ZPeCB4e2IJc8s0l38uh30OmH/xSXE7+STpMJaphHbFJYtl7U/Y7bgWhJtQri+GJsp25PyNRzioabAE="
  },
  "id": 1
```

* get blockbyhash

```bash
usage: tbears blockbyhash [-h] [-u URI] [-c CONFIG] hash

// Example

(venv) $ tbears blockbyhash -u http://127.0.0.1:9100/api/v3 0xce00facd0ac3832e1e6e623d8f4b9344782da881e55abb48d1494fde9e465f78

// Result is same as above.
```

* get totalsupply

```bash
usage: tbears totalsupply [-h] [-u URI] [-c CONFIG]

// Example
(venv) $ tbears totalsupply -u http://127.0.0.1:9100/api/v3

// Result
Total supply of ICX in hex: 0x2961fff8ca4a62327800000
Total supply of ICX in decimal: 800460000000000000000000000
```

* Create your account on Mainnet if you don't have one.
For Mainnet, we recommend you to create your account on Official ICONex application.

1. Go to our website at https://icon.foundation
2. Click ‘Wallet’ button on the top
3. Move to Chrome extension page (https://chrome.google.com/webstore/detail/iconex-beta/flpiciilemghbmfalicajoolhkkenfel?hl=en)
4. Click “Add on +CHROME” button on the upper right corner

* get balance

```bash
usage: tbears balance [-h] [-u URI] [-c CONFIG] address

// Example
(venv) $ tbears balance -u http://127.0.0.1:9100/api/v3 hx63499c4efc26c9370f6d68132c116d180d441266

// Result
balance in hex: 0xde0b6b3a7640000
balance in decimal: 1000000000000000000
```

* Send transaction

Now that you have received a sufficient amount of icx, you can use it to send transactions.

```
usage: tbears sendtx [-h] [-u URI] [-k KEYSTORE] [-c CONFIG] json_file

Request icx_sendTransaction with the specified json file and keystore file. If
keystore file is not given, tbears sends request as it is in the json file.

positional arguments:
  json_file             File path containing icx_sendTransaction content

optional arguments:
  -h, --help            show this help message and exit
  -u URI, --node-uri URI
                        URI of node (default: http://127.0.0.1:9000/api/v3)
  -k KEYSTORE, --key-store KEYSTORE
                        Keystore file path. Used to generate "from" address and
                        transaction signature
  -c CONFIG, --config CONFIG
                        Configuration file path. This file defines the default
                        value for the "uri" (default: ./tbears_cli_config.json)
```

For the details, please go to [Command-line Interfaces(CLIs)](https://github.com/icon-project/t-bears#command-line-interfacesclis) chapter in t-bears repository.

#### Clean Up (delete log / delete DB)

```
$ rm -rf log/
$ rm -rf .storage_test/ .storage_main/
```

## License

This project follows the Apache 2.0 License. Please refer to [LICENSE](https://www.apache.org/licenses/LICENSE-2.0) for details.
