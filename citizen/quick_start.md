## Quick Start Guide for Citizen Node

## Make Virtual Env for Python 3.7.x
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

## necessary tools for package install
automake, pkg-config, libtool, leveldb, rabbitmq, openssl

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
