# Run Citizen Node on ICON network

The citizen node is the node that has the equivalent block data from other nodes but does not join the consensus process.
For detailed information about ICON Network, Pleases refer to [ICON Network](https://github.com/icon-project/icon-project.github.io/blob/master/docs/icon_network.md#icon-network).

* [Run Citizen Node on ICON Testnet network](#run-citizen-node-on-icon-testnet-network)
* [Run Citizen Node on ICON Mainnet network](#run-citizen-node-on-icon-mainnet-network)

## Run Citizen Node on ICON Testnet network

This command will enable ICON citizen node on Testnet network, running on port **9000**.

```bash
$ loop citizen -r testnet
```

Once it's connected to the network, it will start to sync all the blocks on the ICON testnet network.

```
                 ##
         #     ###
      #######  ###
     ########
    ####   #          ###   #######    #######   ###   ###  ###      #######     ######    #######
   ####       ##      ###  #########  #########  ####  ###  ###     #########   ########   ########
   ###       ###      ### ###    ### ###    ###  ##### ###  ###     ###    ### ###    ###  ##    ##
   ##         ##      ### ###        ###     ### ##### ###  ###     ##     ### ##      ##  ##    ##
   ##         ##      ### ##         ###     ### ## ######  ###     ##      ## ##      ##  ##    ##
   ###        ##      ### ###     ## ###     ##  ##  #####  ###     ##     ### ##     ###  ########
   ###       ###      ### ####   ### ####   ###  ##   ####  ###     ###   #### ###   ####  #######
    #       ####      ###  ########   ########   ##    ###  #######  ########   ########   ##
       ########       ###   ######     ######    ##    ###  ######    ######     ######    ##
  ## #########
 ####  #####
  ###

Input your keystore password for channel(icon_dex):  # type your password 
0208 10:50:09,502 57148 4424140224 hx592bb6  INFO peer_service.py(265) run peer_id : hx592bb67a39738a13343548808841db3c9cc35c4f
...
0208 14:19:49,954 99423 4688704960 hx592bb6 icon_dex INFO peer_manager.py(813) This node(hx592bb67a39738a13343548808841db3c9cc35c4f) will run as CitizenNode
0208 14:19:49,955 99423 123145363345408 hx592bb6 icon_dex INFO grpc_helper.py(76) Client Channel : test-ctz.solidwallet.io, secure level : SSLAuthType.none
0208 14:19:50,307 99423 123145363345408 hx592bb6 icon_dex INFO block_manager.py(498) In block height sync max: 51739 yours: -1
0208 14:19:50,660 99423 123145363345408 hx592bb6 icon_dex INFO blockchain.py(250) ADD BLOCK HEIGHT : 0 , HASH : 885b8021826f7e741be7f53bb95b48221e9ab263f377e997b2e47a7b8f4a2a8b , CHANNEL : icon_dex
0208 14:19:51,019 99423 123145363345408 hx592bb6 icon_dex INFO blockchain.py(250) ADD BLOCK HEIGHT : 1 , HASH : d5629fe006104df557570ce2613c8df1901d8f6f322b9f251645c201fa1d1e9e , CHANNEL : icon_dex
```

If you want to browse and search the blocks and transactions in ICON Testnet, please go to [ICON testnet tracker](https://trackerdev.icon.foundation).

### Test through command line interface for ICON

T-Bears is a suite of development tools for SCORE and provides the command line interface to interact with the ICON network including all the JSON-RPC v3 APIs.
For a detailed usage guideline, please refer to [T-Bears tutorial](https://github.com/icon-project/t-bears).

#### tbears console

T-Bears interactive mode using IPython. For default, you can attach to local ip and 9000 port, which is your testnet citizen setting.

```bash
$ tbears console

Python 3.6.5
Type 'copyright', 'credits' or 'license' for more information
IPython 6.4.0 -- An enhanced Interactive Python. Type '?' for help.

IPython profile: tbears

tbears)
```

Now you have attached an interactive shell to a running ICON citizen node on testnet. 

* lastblock

This method returns the last block the Citizen node has currently synced.

```javascript
tbears) lastblock

// result example
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

* blockbyheight

In v3 api, please note that all parameters in request are required to include '0x' at the front.

```javascript
tbears) blockbyheight 0x1

// result example
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

* blockbyhash

```bash
tbears) blockbyhash 0xce00facd0ac3832e1e6e623d8f4b9344782da881e55abb48d1494fde9e465f78

// Result is same as above.
```

* totalsupply

```bash
tbears) totalsupply

// result
Total supply of ICX in hex: 0x2961fff8ca4a62327800000
Total supply of ICX in decimal: 800460000000000000000000000
```

* balance

```bash
tbears) balance {your_address}

// Result
balance in hex: {your balance in hex}
balance in decimal: {your balance in decimal}
```

For there's no balance on new address, you need to request some testnet icx to it. **Please refer to [here](https://github.com/icon-project/icon-project.github.io/blob/master/docs/icon_network.md#testnet-for-exchanges) for test icx and detailed ICON testnet network information.**
Please note that the `Testnet node url` of your citizen node is `https://test-ctz.solidwallet.io` when sending the request email.

If you want to load and view your testnet account on ICONex Chrome extension, please refer [here](https://github.com/icon-project/icon-project.github.io/blob/master/docs/icon_network.md#how-to-change-network-in-iconex-chrome-extension).

* Send transaction

Now that you have received a sufficient amount of icx, you can use it to send transactions.
We provided the minimal settings for the simple coin transfer in the `sendtx_testnet.json` file.
The address to which icx is sent(`to`) is the address the ICON developers usually use when testing. Default value is 0 ICX and you can change the address or add some value if you want.

```javascript
// sendtx_testnet.json
{
  "jsonrpc": "2.0",
  "method": "icx_sendTransaction",
  "params": {
    "to": "hx670e692ffd3d5587c36c3a9d8442f6d2a8fcc795",  // default address for testing
    "nid": "0x2"  // network id for testnet
  },
  "id": 1
}
```

Example

```bash
tbears) sendtx -k my_keystore.json sendtx_testnet.json

input your keystore password:

Send transaction request successfully.
transaction hash: {your tx hash}
```

For more JSON-RPC APIs provided by tbears, please go to [Command-line Interfaces(CLIs)](https://github.com/icon-project/t-bears#command-line-interfacesclis) chapter in t-bears repository.

## Run Citizen Node on ICON Mainnet network

This command below will enable ICON citizen node on Mainnet network, running on port **9100**.

```bash
$ loop citizen -r mainnet
```

Once it's connected to the network, it will start to sync all the blocks on the ICON mainnet network.

```
                 ##
         #     ###
      #######  ###
     ########
    ####   #          ###   #######    #######   ###   ###  ###      #######     ######    #######
   ####       ##      ###  #########  #########  ####  ###  ###     #########   ########   ########
   ###       ###      ### ###    ### ###    ###  ##### ###  ###     ###    ### ###    ###  ##    ##
   ##         ##      ### ###        ###     ### ##### ###  ###     ##     ### ##      ##  ##    ##
   ##         ##      ### ##         ###     ### ## ######  ###     ##      ## ##      ##  ##    ##
   ###        ##      ### ###     ## ###     ##  ##  #####  ###     ##     ### ##     ###  ########
   ###       ###      ### ####   ### ####   ###  ##   ####  ###     ###   #### ###   ####  #######
    #       ####      ###  ########   ########   ##    ###  #######  ########   ########   ##
       ########       ###   ######     ######    ##    ###  ######    ######     ######    ##
  ## #########
 ####  #####
  ###

Input your keystore password for channel(icon_dex):  # type your password 
0208 10:50:09,502 57148 4424140224 hx592bb6  INFO peer_service.py(265) run peer_id : hx592bb67a39738a13343548808841db3c9cc35c4f
...
0208 14:19:49,954 99423 4688704960 hx592bb6 icon_dex INFO peer_manager.py(813) This node(hx592bb67a39738a13343548808841db3c9cc35c4f) will run as CitizenNode
0208 14:19:49,955 99423 123145363345408 hx592bb6 icon_dex INFO grpc_helper.py(76) Client Channel : ctz.solidwallet.io, secure level : SSLAuthType.none
0208 15:39:25,909 16603 123145513943040 hxc57725 icon_dex INFO block_manager.py(498) In block height sync max: 189824 yours: -1
0208 14:19:50,660 99423 123145363345408 hx592bb6 icon_dex INFO blockchain.py(250) ADD BLOCK HEIGHT : 0 , HASH : cf43b3fd45981431a0e64f79d07bfcf703e064b73b802c5f32834eec72142190 , CHANNEL : icon_dex
0208 14:19:51,019 99423 123145363345408 hx592bb6 icon_dex INFO blockchain.py(250) ADD BLOCK HEIGHT : 1 , HASH : 3add53134014e940f6f6010173781c4d8bd677d9931a697f962483e04a685e5c , CHANNEL : icon_dex

```

If you want to browse and search the blocks and transactions in ICON Mainnet, please go to [ICON tracker](https://tracker.icon.foundation).

### Test through command line interface for ICON

#### tbears genconf

Since default setting for tbears is 9000 port, you need to change the port setting by configuration. 

```bash
$ tbears genconf
Made tbears_cli_config.json, tbears_server_config.json, keystore_test1 successfully
```

Move on to `tbears_cli_config.json` and change the `uri` as below. 

```javascript
// tbears_cli_config.json
{
    "uri": "http://127.0.0.1:9100/api/v3", // ==> change 9000 to 9100
    "nid": "0x3",
    "keyStore": null,
    "from": "hxe7af5fcfd8dfc67530a01a0e403882687528dfcb",
    "to": "cx0000000000000000000000000000000000000000",
    "deploy": {
        "stepLimit": "0x10000000",
        "mode": "install",
        "scoreParams": {}
    },
    "txresult": {},
    "transfer": {
        "stepLimit": "0xf4240"
    }
}
```

#### tbears console

T-Bears interactive mode using IPython.

```bash
$ tbears console

Python 3.6.5
Type 'copyright', 'credits' or 'license' for more information
IPython 6.4.0 -- An enhanced Interactive Python. Type '?' for help.

IPython profile: tbears

tbears)
```

Now you have attached an interactive shell to a running ICON citizen node on mainnet. 

#### Test jsonRPC APIs
In v3, parameters in all api request params require the string '0x' at the front.

* lastblock

This method returns the last block the Citizen node has currently synced.

```javascript
tbears) lastblock

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

* blockbyheight

```javascript
tbears) blockbyheight 0x1

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

* blockbyhash

```bash
tbears) blockbyhash 0xce00facd0ac3832e1e6e623d8f4b9344782da881e55abb48d1494fde9e465f78

// Result is same as above.
```

* totalsupply

```bash
tbears) totalsupply

// Result
Total supply of ICX in hex: 0x2961fff8ca4a62327800000
Total supply of ICX in decimal: 800460000000000000000000000
```

* To send transaction on Mainnet, you need an ICON account and a balance. If you don't have on, please create your account on official ICONex application as guide below.

1. Go to our website at https://icon.foundation
2. Click ‘Wallet’ button on the top
3. Move to Chrome extension page (https://chrome.google.com/webstore/detail/iconex-beta/flpiciilemghbmfalicajoolhkkenfel?hl=en)
4. Click “Add on +CHROME” button on the upper right corner

**For detailed ICON mainnet network information, please refer to [here](https://github.com/icon-project/icon-project.github.io/blob/master/docs/icon_network.md#mainnet).**

* balance

```bash
tbears) balance hx63499c4efc26c9370f6d68132c116d180d441266

// Result
balance in hex: {your balance in hex}
balance in decimal: {your balance in decimal}
```

* Send transaction

If you have sufficient amount of icx, you can use it to send transactions.

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

For more JSON-RPC APIs provided by tbears, please go to [Command-line Interfaces(CLIs)](https://github.com/icon-project/t-bears#command-line-interfacesclis) chapter in t-bears repository.
