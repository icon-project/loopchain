## Quick Start Guide for Citizen Node

## Setting build environment
 * install libraries

 ```
 $ sudo apt update
 $ sudo apt install -y make build-essential libssl-dev zlib1g-dev libbz2-dev \
   libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev libncursesw5-dev \
   xz-utils tk-dev libffi-dev liblzma-dev automake libtool
 ```

 * ubuntu 18.04 need install secp256k1 library

 ```
 $ sudo apt install -y libsecp256k1-dev
 ```

## Python Installation

Python 3.7.x

 * Install **pyenv**

 ```
 $ curl -L https://github.com/pyenv/pyenv-installer/raw/master/bin/pyenv-installer | bash
 ```

 * Append the following commands to ~/.profile

 ```
 export PATH="$HOME/.pyenv/bin:$PATH"
 eval "$(pyenv init -)"
 eval "$(pyenv virtualenv-init -)"
 ```

 * Apply for the profile

 ```
 $ source ~/.profile
 ```

 * Install **python 3.7.x**

 ```
 $ pyenv install 3.7.x
 $ pyenv shell 3.7.x
 $ python -V # check python version
 ```

 ## Make Virtual Environment
  * Change working directory to citizen pack directory.

  ```
  $ cd citizen_pack
  ```

  * Install virtualenv

  ```
  $ pip3 install virtualenv
  ```

  * make virtual environment and apply
  ```
  $ virtualenv -p python venv
  $ source venv/bin/activate
  ```

## RabbitMQ Server Installation
 For the reliable installation, please visit: [Downloading and Installing RabbitMQ]

## Install loopchain packages
```
$ pip3 install ./whl/iconcommons*.whl \
&& pip3 install ./whl/iconrpcserver*.whl \
&& pip3 install ./whl/iconservice*.whl \
&& pip3 install ./whl/loopchain*.whl \
&& pip3 install ./whl/earlgrey*.whl
```

> install `icon_rc` to your $PATH directory. for example, `/usr/local/bin`
```
$ install -m 755 icon_rc $SOME_DIR_IN_PATH
```

> check `icon_rc` version
```
$ icon_rc -version
icon_rc vx.y.z, tags()-YYYY-MM-DD-HH:MM:SS
```

## Make key file with pass phrase.
```
$ mkdir keys
$ openssl ecparam -genkey -name secp256k1 | openssl ec -aes-256-cbc -out ./keys/my_private.pem
```

## Change configuration. (password for your key file)
> In the ```./conf/citizen_{testnet or mainnet}.json``` configuration file, change the following configuration value.

```
{
  "PRIVATE_PASSWORD": "password",  <==== NEED TO CHANGE
  ...
}
```

## Run Citizen Node to Testnet ICON Network
```
$ ./run_citizen_testnet.sh
```

## Run Citizen Node to Testnet ICON Network
```
$ ./run_citizen_mainnet.sh
```

## Stop all

```
$ ./stop_all.sh
```

## Clean up (delete log, delete db)
```
$ rm -rf log
$ rm -rf .storage*
```

[Downloading and Installing RabbitMQ]: https://www.rabbitmq.com/download.html
