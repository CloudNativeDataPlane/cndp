# CNDP - Cloud Native Data Plane

## Installation Guide

This document assumes you are building on an Ubuntu 21.04 host. It provides minimal
instructions to run CNDP applications. For more information, refer to the CNDP documentation.

## Prerequisites

If behind a proxy server you may need to setup a number of configurations to allow access via the server.
Some commands i.e. apt-get, git, ssh, curl, wget and others will need configuration to work correctly.
Please refer to apt-get, git and other documentations to enable access through a proxy server.

### dependencies

The following package are required to build CNDP libraries and examples.

```bash
sudo apt-get update && sudo apt-get install -y \
    build-essential libbsd-dev libelf-dev libjson-c-dev libnl-3-dev libnl-cli-3-dev libnuma-dev \
    libpcap-dev meson pkg-config
```

#### Optional packages needed to build documentation

```bash
sudo apt-get install -y doxygen python3-sphinx
```

### libbpf

The [libbpf](https://github.com/libbpf/libbpf) is a dependency of CNDP. Starting with Ubuntu 20.10
it can be installed using apt. For earlier Ubuntu versions, or for users who want the latest code,
it can be installed from source.

#### _Note:_

Newer versions of libbpf greater than or equal to v0.7.0 require _libxdp_ to be installed. For now we
can checkout a previous version v0.5.0 or v0.6.1 instead of installing _libxdp_.

### Install libbpf-dev from package manager

Use the following command on Ubuntu 20.10 and later to install the headers and libraries to build
and run CNDP applications. If using an earlier Ubuntu version, you need to build libbpf from source.

```bash
sudo apt-get install -y libbpf-dev
```

### Install libbpf from source

```bash
git clone https://github.com/libbpf/libbpf.git
cd libbpf
git checkout v0.5.0  # or v0.6.1 if needing a newer version
make -C src && sudo make -C src install
```

The library and pkgconfig file is installed to /usr/lib64, which is not where the loader or
pkg-config looks. Fix this by editing the ldconfig file as suggested below.

```bash
sudo vim /etc/ld.so.conf.d/x86_64-linux-gnu.conf
# add a line with /usr/lib64 to the bottom of the file, save and exit.
sudo ldconfig
```

The following statement may be necessary if libbpf is installed from source instead of the package manager.

```bash
export PKG_CONFIG_PATH=/usr/lib64/pkgconfig
```

## Build CNDP

### Clone and build CNDP

```bash
git clone https://github.com/CloudNativeDataPlane/cndp.git
cd cndp
make
```

Other targets exist, most are wrappers around tools/cne-build.sh.

```bash
make help
or
make rebuild # rebuild will clean and build CNDP with -O3
or
make clean debug # to build a debug image with -O0
or
make docs
```

## Run CNDP examples

### helloworld

The most basic example is `helloworld`.

```bash
./builddir/examples/helloworld/helloworld

Max threads: 512, Max lcores: 32, NUMA nodes: 1, Num Threads: 1
hello world! from thread index 0 for index 0
Ctrl-C to exit
```

### cndpfwd

An example that uses networking is `cndpfwd`. It requires the underlying network interface
uses, e.g. AF_XDP sockets. Make sure the kernel on which you intend to run the application
supports AF_XDP sockets, i.e. CONFIG_XDP_SOCKETS=y.

```bash
grep XDP_SOCKETS= /boot/config-`uname -r`
```

Configure an ethtool filter to steer packets to a specific queue.

```bash
sudo ethtool -N <devname> flow-type udp4 dst-port <dport> action <qid>
sudo ip link set dev <devname> up
```

Instruct `cndpfwd` to receive, count, and drop all packets on the previously configured
queue. To configure `cndpfwd`, edit the examples/cndpfwd/fwd.jsonc configuration file. Make
sure the "lports" section has the same netdev name and queue id for which the ethtool filter
is configured. Make sure the "threads" section has the correct "lports" configured. Then
launch the application, specifying the updated configuration file.

```bash
sudo ./builddir/examples/cndpfwd/cndpfwd -c examples/cndpfwd/fwd.jsonc drop
```
