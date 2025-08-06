# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020-2025 Intel Corporation.
# Copyright (c) 2024 Red Hat Inc.

FROM ubuntu:24.04

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
    python3-pip \
    python3.12-venv \
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

# Set PKG_CONFIG_PATH to resolve libbpf dependency for Rust library build.
ENV PKG_CONFIG_PATH="/usr/lib64/pkgconfig"

RUN python3 -m venv /opt/cndp-venv
ENV PATH=/opt/cndp-venv/bin:$PATH
RUN echo "source /opt/cndp-venv/bin/activate" >> "${HOME}/.bashrc"
