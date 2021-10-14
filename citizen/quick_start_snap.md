## Quick Start Guide for Citizen Node

## install [snapd](https://docs.snapcraft.io/installing-snapd)
 * ubuntu is pre-installed on 16.04.4 LTS (Xenial Xerus) or later.
 ```
 $ snap version
 snap    2.36.1
 snapd   2.36.1
 series  16
 ubuntu  18.04
 kernel  4.15.0-39-generic
 ```

 * [centos](https://docs.snapcraft.io/installing-snap-on-centos)
 ```
 $ sudo yum install epel-release
 $ sudo yum install snapd
 $ sudo systemctl enable --now snapd.socket
 $ sudo ln -s /var/lib/snapd/snap /snap
 ```

 _Either logout and back in again, or restart your system, to ensure snap’s paths are updated correctly._

## loopchain installation

 * install for the first time
 ```
 $ sudo snap install loopchain
 $ loopchain --help
 ```
 * upgrade to new revision
 ```
 $ sudo snap refresh loopchain
 ```

## RabbitMQ Server Installation
 For the reliable installation, please visit: [Downloading and Installing RabbitMQ]

## Mount external storage

 **When you want to store data in an external storage, you can use `/media` or `/mnt`.**

 * First, you have to mount external storage to `/media` or `/mnt` using fstab or manually.
 * Second, create directory for store your data. For example `/media/data`.
   If you run with normal user, you must change owner and group of `/media/data`.
```
 $ sudo mkdir /media/data
 $ sudo chown userid.userid /media/data
```

  * Third, mount your storage data directory to your home data directory.
```
 $ sudo mount -obind /media/data $HOME/data
```

 * see [next section](#copy-default-configure-files) or copy configure files manually

```
 $ cp -a /snap/loopchain/[rev]/conf /snap/loopchain/[rev]/scripts/* $HOME/data
```
 skip **Copy default configure files** section. And you have to run loopchain in `$HOME/data`

## Copy default configure files

 * When loopchain is installed for the first time, `loopchain.init` should be executed.
```
$ loopchain.init [TARGET_DIR]
```
> _If not specified `TARGET_DIR`, default `TARGET_DIR` is `$HOME/snap/loopchain/common`_

 * When upgrading to a new revision, make sure that `$HOME/snap/loopchain/current` points to upgraded revision.
  Otherwise, `loopchain` or `loopchain.init` command should be executed to update link.
```
$ sudo snap refresh loopchain
$ loopchain
```

## Make keystore file with pass phrase.
> _If you have key(der or pem), see [key convert](#key-convert)_

```
$ pip3 install tbears
$ cd $HOME/snap/loopchain/common
$ mkdir keys
$ tbears keystore keys/my_private.json
```

## Default loopchain configurations
 * sample configurations and documents
```
installed loopchain location : /snap/loopchain/current/
guides : /snap/loopchain/current/docs/
configurations : /snap/loopchain/current/conf/
scripts : /snap/loopchain/current/scripts/
 ```

## Change configuration. (password for your key file)
> In the ```conf/citizen_{testnet or mainnet}.json``` configuration file, change the following configuration value.

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

## Key convert
> Convert der, pem to json keystore file.
> After convert key to json, you need to update the conf.
```
$ loopchain -o conf/citizen_mainnet.conf -k
```

[Downloading and Installing RabbitMQ]: https://www.rabbitmq.com/download.html
