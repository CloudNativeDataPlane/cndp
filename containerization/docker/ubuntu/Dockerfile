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
    wget \
    llvm-dev \
    libclang-dev \
    clang \
    curl \
    git \
    gcc-multilib \
    llvm \
    lld \
    m4 \
    linux-tools-common \
    libbpf-dev \
    && rm -rf /var/lib/apt/lists/*

# Install libxdp
RUN git clone https://github.com/xdp-project/xdp-tools.git
WORKDIR /xdp-tools/
RUN git checkout v1.2.2
RUN ./configure
WORKDIR /xdp-tools/
RUN make -j; PREFIX=/usr make -j install
ENV PKG_CONFIG_PATH=/usr/lib/pkgconfig

# Install Rust and Cargo.
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y

# Set Cargo path.
ENV PATH="/root/.cargo/bin:${PATH}"

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

# Build and install Rust packet fwd example application.
WORKDIR /cndp/lang/rs
# Set PKG_CONFIG_PATH to resolve libbpf dependency for Rust library build.
ENV PKG_CONFIG_PATH="/usr/lib64/pkgconfig"
RUN CNDP_INSTALL_PATH="/cndp" cargo install --root /cndp/usr/local/ --path examples/fwd

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
    libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

# Copy artifacts from the build container
COPY --from=build /cndp/usr/local/bin/cndpfwd /usr/bin/
COPY --from=build /cndp/usr/local/bin/fwd /usr/bin
COPY --from=build /cndp/usr/local/lib/x86_64-linux-gnu/*.so /usr/lib/
COPY --from=build /cndp/lang/go/stats/prometheus/prometheus /usr/bin/
COPY --from=build /lib/x86_64-linux-gnu/libbpf.so.0 /usr/lib/

# Copy configurations from the host
WORKDIR /root
COPY tools/jsonc_gen.sh .
RUN chmod +rwx jsonc_gen.sh
COPY containerization/docker/ubuntu/fwd.jsonc .
COPY lang/go/stats/prometheus/prom_cfg.json .
