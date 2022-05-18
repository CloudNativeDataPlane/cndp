# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020-2022 Intel Corporation.

FROM fedora:35 AS build

# Setup container to build CNDP applications
RUN dnf -y upgrade && dnf -y install \
    @development-tools \
    libbsd-devel \
    json-c-devel \
    libnl3-devel \
    libnl3-cli \
    numactl-libs \
    libbpf-devel \
    libbpf \
    meson \
    ninja-build \
    gcc-c++ \
    libpcap \
    libpcap-devel \
    golang

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

WORKDIR /cndp
