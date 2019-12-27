# Create snap for loopchain

## Table of contents

 1. [base docker image(include golang) for snapcraft](#build-docker-image)
 1. [prepare assets](#prepare-assets)
 1. [snapcraft build](#snapcraft-build)

## Build docker image

 **snapcraft build with docker, reference of [docker base]**

 1. change to directory in Dockerfile
 1. build docker image. for example,
 ```
 $ docker build --rm -t snapcraft:tagname --build-arg UBUNTU=bionic --build-arg GO_VERSION=1.12 --no-cache .
 ```
 you can use two arguments. `UBUNTU, GO_VERSION`.
 `UBUNTU` is base docker tag of ubuntu(default is `bionic`) and `GO_VERSION` is golang version(default is `1.12`).

 * If you want, download from [my docker hub]

## Prepare assets

 1. create asset directory
  ```bash
  $ mkdir assets && cd assets
  ```
 2. create `checkout_branch.sh`
 * change [loopchain] branch that want to build.
 ```bash
 #!/bin/bash

 LOOPCHAIN_BRANCH=develop

 if [[ ${LOOPCHAIN_BRANCH} == "master" ]]; then
     echo "current branch is master. nothing to change!"
     exit
 fi
 git checkout ${LOOPCHAIN_BRANCH}
 ```
 3. create `rc_checkout_branch.sh`
 * change [rewardcalculator] branch that want to build.

 ```bash
 #!/bin/bash

 RC_BRANCH=develop

 if [[ ${RC_BRANCH} == "master" ]]; then
     echo "current branch is master. nothing to change!"
     exit
 fi
 git checkout ${RC_BRANCH}
 ```
 4. create `requirements_snap.txt`
  * change branch or tag that want to build.
 ```
 git+https://github.com/icon-project/icon-service.git@master
 git+https://github.com/icon-project/icon-commons.git@master
 git+https://github.com/icon-project/icon-rpc-server.git@master
 ```
 5. copy snapcraft.yaml
 ```bash
 $ cp -a loopchain/snap* assets/
 ```

## Snapcraft build
 1. run docker image for snapcraft
 ```bash
 $ docker run --rm -it -v $PWD:/mnt/snap snapcraft:tagname /bin/bash
 ```
 2. create `build_snap` directory
 ```bash
 $ cd && mkdir build_snap
 ```
 3. copy assets
 ```bash
 $ cp /mnt/snap/assets/checkout_branch.sh /mnt/snap/assets/rc_checkout_branch.sh /mnt/assets/requirements_snap.txt build_snap/
 ```
 4. copy snapcraft.yaml
 ```bash
 $ cp -a /mnt/snap/assets/snap* build_snap/
 ```
 5. start build
 ```bash
 $ cd build_snap
 $ snapcraft -d
 ```

[docker base]: https://github.com/snapcore/snapcraft/blob/master/docker
[my docker hub]: https://hub.docker.com/r/yakkle/snapcraft
[loopchain]: https://github.com/icon-project/loopchain
[rewardcalculator]: https://github.com/icon-project/rewardcalculator
