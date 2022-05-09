# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020-2022 Intel Corporation.

FROM ubuntu:22.04 AS build

# Setup container to build CNDP applications
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    build-essential \
    golang \
    libelf-dev \
    meson \
    pkg-config \
    libbsd-dev \
    libjson-c-dev \
    libnl-3-dev \
    libnl-cli-3-dev \
    libnuma-dev \
    libpcap-dev \
    wget

# Build and install libbpf version >=0.3.0 and <=0.6.1
SHELL ["/bin/bash", "-c"]
RUN set -o pipefail \
    && wget -q -O - https://github.com/libbpf/libbpf/archive/refs/tags/v0.5.0.tar.gz \
    | tar -xzC / \
    && make -j -C /libbpf-0.5.0/src install

# Copy CNDP sources, build, and install
RUN mkdir /cndp
WORKDIR /cndp
COPY doc doc
COPY examples examples
COPY lang lang
COPY lib lib
COPY test test
COPY tools tools
COPY usrtools usrtools
COPY containerization containerization
COPY VERSION Makefile meson.build meson_options.txt ./
RUN make && make install

# Build the prometheus-metrics app
WORKDIR /cndp/lang/go/stats/prometheus
RUN go build prometheus.go

# Setup container to run CNDP applications
FROM ubuntu:22.04

# Ubuntu 20.04 has libjson-c4 but Ubuntu 21.04 has libjson-c5. Try either.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    ethtool \
    libbsd0 \
    libelf1 \
    libjson-c[45] \
    libnl-3-200 \
    libnl-cli-3-200 \
    libnuma1 \
    libpcap0.8

# Copy artifacts from the build container
COPY --from=build /cndp/usr/local/bin/cndpfwd /usr/bin/
COPY --from=build /cndp/usr/local/lib/x86_64-linux-gnu/*.so /usr/lib/
COPY --from=build /cndp/lang/go/stats/prometheus/prometheus /usr/bin/
COPY --from=build /usr/lib64/libbpf.so.0 /usr/lib/

# Copy configurations from the host
WORKDIR /root
COPY tools/jsonc_gen.sh .
RUN chmod +rwx jsonc_gen.sh
COPY containerization/docker/ubuntu/fwd.jsonc .
COPY lang/go/stats/prometheus/prom_cfg.json .
