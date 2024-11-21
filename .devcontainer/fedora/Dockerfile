# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020-2024 Intel Corporation
# Copyright (c) 2024 Red Hat Inc.

FROM fedora:40 AS build

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
	bpftool \
    python3-pip

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
RUN pip install pre-commit
