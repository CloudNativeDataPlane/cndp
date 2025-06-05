# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020-2023 Intel Corporation.

FROM public.ecr.aws/ubuntu/ubuntu:25.04 AS build

# Setup container to build CNDP applications
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    build-essential \
    golang \
    libelf-dev \
    python3-pip \
    pkg-config \
    libbsd-dev \
    libjson-c-dev \
    libnl-3-dev \
    libnl-cli-3-dev \
    libnuma-dev \
    libpcap-dev \
    wget \
    llvm-dev \
    curl \
    git \
    gcc-multilib \
    llvm \
    lld \
    m4 \
    linux-tools-common \
    libbpf-dev \
    ninja-build

# Add LLVM key securely and install Clang 15 from Jammy repo
RUN mkdir -p /etc/apt/keyrings && \
    curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key -o /etc/apt/keyrings/llvm.asc && \
    echo "deb [signed-by=/etc/apt/keyrings/llvm.asc] http://apt.llvm.org/jammy/ llvm-toolchain-jammy-15 main" \
        > /etc/apt/sources.list.d/llvm.list


# Install Clang 15
RUN apt-get update && apt-get install -y clang-15 llvm-15 libclang-15-dev && \
    update-alternatives --install /usr/bin/clang clang /usr/bin/clang-15 100 && \
    update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-15 100

# Install Meson via pip and cleanup
RUN apt-get remove -y meson || true && \
    pip install --no-cache-dir meson --break-system-packages && \
    rm -rf /var/lib/apt/lists/*


# Install libxdp
RUN git clone https://github.com/xdp-project/xdp-tools.git
WORKDIR /xdp-tools/
RUN git checkout v1.2.2
RUN ./configure
# FIX error: 'calloc' sizes specified with 'sizeof' in the earlier argument and not in the later argument [-Werror=calloc-transposed-args]
RUN grep -q 'calloc.*shb_length' lib/util/xpcapng.c && \
    sed -i -E \
    -e 's/calloc\((shb_length),[[:space:]]*1\)/calloc(1, \1)/' \
    -e 's/calloc\((idb_length),[[:space:]]*1\)/calloc(1, \1)/' \
    -e 's/calloc\(\s*sizeof\(\*pd\),[[:space:]]*1\)/calloc(1, sizeof(*pd))/' \
    lib/util/xpcapng.c || echo "Patch already applied or file missing"
RUN make -j; PREFIX=/usr make -j install
ENV PKG_CONFIG_PATH=/usr/lib/pkgconfig

# Install Rust and Cargo.
# RUN curl https://sh.rustup.rs -sSf | sh -s -- -y

# Set Cargo path.
# ENV PATH="/root/.cargo/bin:${PATH}"

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

# RUN apt-get update && apt-get install -y \
#     llvm-17 clang-17 libclang-17-dev \
#     && update-alternatives --install /usr/bin/clang clang /usr/bin/clang-17 100 \
#     && update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-17 100

# ENV LIBCLANG_PATH=/usr/lib/llvm-17/lib
# ENV CLANG_PATH=/usr/bin/clang-17

# # Build and install Rust packet fwd example application.
# WORKDIR /cndp/lang/rs
# # Set PKG_CONFIG_PATH to resolve libbpf dependency for Rust library build.
# ENV PKG_CONFIG_PATH="/usr/lib64/pkgconfig"
# RUN CNDP_INSTALL_PATH="/cndp" cargo install --root /cndp/usr/local/ --path examples/fwd

# Setup container to run CNDP applications
FROM public.ecr.aws/ubuntu/ubuntu:25.04

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
#COPY --from=build /cndp/usr/local/bin/fwd /usr/bin
COPY --from=build /cndp/usr/local/lib/x86_64-linux-gnu/*.so /usr/lib/
COPY --from=build /cndp/lang/go/stats/prometheus/prometheus /usr/bin/
COPY --from=build /usr/lib*/libbpf.so* /usr/lib/
COPY --from=build /lib/libxdp.so.1 /usr/lib/

# Copy configurations from the host
WORKDIR /root
COPY tools/jsonc_gen.sh .
RUN chmod +rwx jsonc_gen.sh
COPY containerization/docker/ubuntu/fwd.jsonc .
COPY lang/go/stats/prometheus/prom_cfg.json .
