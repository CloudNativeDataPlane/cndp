# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020-2023 Intel Corporation.

FROM fedora:41 AS build

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
    golang \
	clang \
	llvm \
	m4 \
	bpftool

# Install libxdp
RUN git clone https://github.com/xdp-project/xdp-tools.git
WORKDIR /xdp-tools/
RUN ./configure
RUN make -j; PREFIX=/usr make -j install
ENV PKG_CONFIG_PATH=/usr/lib/pkgconfig

# Install Rust bindgen dependencies.
RUN dnf -y install clang-devel curl

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
# 'fwd' binary will be installed in /cndp/usr/local/bin
WORKDIR /cndp/lang/rs
RUN CNDP_INSTALL_PATH="/cndp" cargo install --root /cndp/usr/local/ --path examples/fwd

WORKDIR /cndp
