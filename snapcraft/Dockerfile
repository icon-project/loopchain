# reference to below link
# https://github.com/snapcore/snapcraft/blob/master/docker/stable.Dockerfile
# https://forum.snapcraft.io/t/creating-docker-images-for-snapcraft/11739
# https://github.com/golang/go/wiki/Ubuntu
ARG GO_VERSION=1.12
ARG UBUNTU=bionic

FROM ubuntu:$UBUNTU as builder
ARG UBUNTU
ARG GO_VERSION

RUN echo "build from ubuntu:$UBUNTU, go version : $GO_VERSION"

# Grab dependencies
RUN apt-get update
RUN apt-get dist-upgrade --yes
RUN apt-get install --yes curl jq squashfs-tools software-properties-common
RUN add-apt-repository -y ppa:longsleep/golang-backports
RUN apt-get update -qy
RUN apt-get install -y golang-$GO_VERSION

# Grab the core snap from the stable channel and unpack it in the proper place
RUN curl -L $(curl -H 'X-Ubuntu-Series: 16' 'https://api.snapcraft.io/api/v1/snaps/details/core' | jq '.download_url' -r) --output core.snap
RUN mkdir -p /snap/core
RUN unsquashfs -d /snap/core/current core.snap

# Grab the snapcraft snap from the stable channel and unpack it in the proper place
RUN curl -L $(curl -H 'X-Ubuntu-Series: 16' 'https://api.snapcraft.io/api/v1/snaps/details/snapcraft?channel=stable' | jq '.download_url' -r) --output snapcraft.snap
RUN mkdir -p /snap/snapcraft
RUN unsquashfs -d /snap/snapcraft/current snapcraft.snap

# Create a snapcraft runner (TODO: move version detection to the core of snapcraft)
RUN mkdir -p /snap/bin
RUN echo "#!/bin/sh" > /snap/bin/snapcraft
RUN snap_version="$(awk '/^version:/{print $2}' /snap/snapcraft/current/meta/snap.yaml)" && echo "export SNAP_VERSION=\"$snap_version\"" >> /snap/bin/snapcraft
RUN echo 'exec "$SNAP/usr/bin/python3" "$SNAP/bin/snapcraft" "$@"' >> /snap/bin/snapcraft
RUN chmod +x /snap/bin/snapcraft

# Multi-stage build, only need the snaps from the builder. Copy them one at a
# time so they can be cached.
FROM ubuntu:$UBUNTU
ARG GO_VERSION

RUN echo "go version : $GO_VERSION"

COPY --from=builder /snap/core /snap/core
COPY --from=builder /snap/snapcraft /snap/snapcraft
COPY --from=builder /snap/bin/snapcraft /snap/bin/snapcraft
COPY --from=builder /usr/lib/go-$GO_VERSION /usr/lib/go
COPY --from=builder /usr/share/go-$GO_VERSION /usr/share/go-$GO_VERSION

RUN ln -sf /usr/lib/go/bin/go /usr/bin/go
RUN ln -sf /usr/lib/go/bin/gofmt /usr/bin/gofmt

# Generate locale
RUN apt-get update && apt-get dist-upgrade --yes && apt-get install --yes sudo locales && locale-gen en_US.UTF-8

# Set the proper environment
ENV LANG="en_US.UTF-8"
ENV LANGUAGE="en_US:en"
ENV LC_ALL="en_US.UTF-8"
ENV PATH="/snap/bin:$PATH"
ENV SNAP="/snap/snapcraft/current"
ENV SNAP_NAME="snapcraft"
ENV SNAP_ARCH="amd64"
