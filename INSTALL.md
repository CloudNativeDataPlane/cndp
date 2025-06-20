# CNDP - Cloud Native Data Plane

## Ubuntu Installation Instructions

This section assumes you are building on an Ubuntu 21.04 host. It provides
minimal instructions to run CNDP applications. For more information, refer to
the CNDP documentation.

### Ubuntu Prerequisites

If behind a proxy server you may need to setup a number of configurations to
allow access via the server. Some commands i.e. apt-get, git, ssh, curl, wget
and others will need configuration to work correctly. Please refer to apt-get,
git and other documentations to enable access through a proxy server.

### Ubuntu Dependencies

The following package are required to build CNDP libraries and examples.

```bash
sudo apt-get update && sudo apt-get install -y \
    build-essential libbsd-dev libelf-dev libjson-c-dev libnl-3-dev libnl-cli-3-dev libnuma-dev \
    libpcap-dev meson pkg-config
```

### Hyperscan support

The cndpfwd example application supports a simple hyperscan forwarding type
mode. The Hyperscan forwarding mode uses expressions in Hyperscan style in the
jsonc file in options.hs_patterns array. The example can be expanded to be a
DDOS or DPI or a load balancer using Hyperscan. If wanting to try Hyperscan you
must install Hyperscan. Ubuntu has a package which can be installed to enable
the build process to detect and use Hyperscan.

```bash
sudo apt-get install -y libhyperscan-dev # In Ubuntu 22.10 the Hyperscan version is 5.4.0
```

#### Optional packages needed to build documentation

```bash
sudo apt-get install -y doxygen python3-sphinx
```

### libbpf

The [libbpf](https://github.com/libbpf/libbpf) is a dependency of CNDP. Starting
with Ubuntu 20.10 it can be installed using apt. For earlier Ubuntu versions, or
for users who want the latest code, it can be installed from source.

> **_NOTE:_** Newer versions of libbpf greater than or equal to v0.7.0 require
> _libxdp_ to be installed. For now we can checkout a previous version v0.5.0 or
> v0.6.1 instead of installing _libxdp_.

### Install libbpf-dev from package manager

Use the following command on Ubuntu 20.10 and later to install the headers and
libraries to build and run CNDP applications. If using an earlier Ubuntu
version, you need to build libbpf from source.

```bash
sudo apt-get install -y libbpf-dev
```

### Install libbpf from source

```bash
git clone https://github.com/libbpf/libbpf.git
cd libbpf
git checkout v0.5.0 # or v0.6.1 if needing a newer version
make -C src && sudo make -C src install
```

The library and pkgconfig file is installed to /usr/lib64, which is not where
the loader or pkg-config looks. Fix this by editing the ldconfig file as
suggested below.

```bash
sudo vim /etc/ld.so.conf.d/x86_64-linux-gnu.conf
# add a line with /usr/lib64 to the bottom of the file, save and exit.
sudo ldconfig
```

The following statement may be necessary if libbpf is installed from source
instead of the package manager.

```cmd
export PKG_CONFIG_PATH=/usr/lib64/pkgconfig
```

### Install libxdp from source

Install dependencies:

```cmd
sudo apt-get update; sudo apt-get install -y git gcc-multilib clang llvm lld m4
```

Clone libxdp:

```cmd
git clone https://github.com/xdp-project/xdp-tools.git
cd xdp-tools/
```

Run ./configure

```bash
./configure
Found clang binary 'clang' with version 14 (from 'Ubuntu clang version 14.0.0-1ubuntu1')
libbpf support: Submodule 'libbpf' (https://github.com/xdp-project/libbpf/) registered for path 'lib/libbpf'
Cloning into '/xdp-tools/lib/libbpf'...
Submodule path 'lib/libbpf': checked out '87dff0a2c775c5943ca9233e69c81a25f2ed1a77'
submodule v0.8.0
  perf_buffer__consume support: yes (submodule)
  btf__load_from_kernel_by_id support: yes (submodule)
  btf__type_cnt support: yes (submodule)
  bpf_object__next_map support: yes (submodule)
  bpf_object__next_program support: yes (submodule)
  bpf_program__insn_cnt support: yes (submodule)
  bpf_map_create support: yes (submodule)
  perf_buffer__new_raw support: yes (submodule)
  bpf_xdp_attach support: yes (submodule)
zlib support: yes
ELF support: yes
pcap support: yes
secure_getenv support: yes
```

Build and install the libbpf git submodule:

```cmd
cd lib/libbpf/
git submodule init && git submodule update
cd src
make CFLAGS+=-fpic; PREFIX=/usr make install
cd -
```

Update pkg-config path as shown in the previous section.

In the top level xdp-tools directory:

```cmd
make -j; PREFIX=/usr make -j install
```

check pkg-config can find libxdp:

```cmd
pkg-config --modversion libxdp
1.2.2
```

on some systems it maybe necessary to run:

```bash
export PKG_CONFIG_PATH=/usr/lib/pkgconfig
```

## Fedora Installation Instructions

This section assumes you are building on a Fedora 35 host with a 5.17.5 Kernel
version. It provides minimal instructions to run CNDP applications. For more
information, refer to the CNDP documentation.

### Fedora dependencies

The following package are required to build CNDP libraries and examples.

```bash
sudo dnf update && sudo dnf -y install \
    @development-tools git libbsd-devel json-c-devel libnl3-devel libnl3-cli \
    numactl-libs libbpf-devel libbpf meson ninja-build gcc-c++ \
    libpcap libpcap-devel libxdp-devel libxdp
```

## Hugepage Configuration

Hugepage support is optional but recommended, as it can significantly improve
performance. For detailed instructions on configuring Hugepages, refer to the
[Linux Getting Started Guide](./doc/guides/linux_gsg/linux_gsg.rst)

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

An example that uses networking is `cndpfwd`. It requires the underlying network
interface uses, e.g. AF_XDP sockets. Make sure the kernel on which you intend to
run the application supports AF_XDP sockets, i.e. CONFIG_XDP_SOCKETS=y.

```bash
grep XDP_SOCKETS= /boot/config-$(uname -r)
```

Configure an ethtool filter to steer packets to a specific queue.

```bash
sudo ethtool -N <devname> flow-type udp4 dst-port <dport> action <qid>
sudo ip link set dev <devname> up
```

Instruct `cndpfwd` to receive, count, and drop all packets on the previously
configured queue. To configure `cndpfwd`, edit the examples/cndpfwd/fwd.jsonc
configuration file. Make sure the "lports" section has the same netdev name and
queue id for which the ethtool filter is configured. Make sure the "threads"
section has the correct "lports" configured. Then launch the application,
specifying the updated configuration file.

```bash
sudo ./builddir/examples/cndpfwd/cndpfwd -c examples/cndpfwd/fwd.jsonc drop
```

### XDP Packet Capture

Packets processed at the XDP hook can't be captured using tcpdump. Instead, it's
recommended to use
[xdpdump](https://github.com/xdp-project/xdp-tools/tree/master/xdp-dump).

The following example shows how to redirect a capture file from xdpdump to
tcpdump for real-time packet decoding:

```bash
xdpdump -i eno1 -w - | tcpdump -r - -n
```

### Debugging packet drops

Silent packet drops for AF_XDP can be debugged using:

- `bpftrace`
- `perf record`

#### bpftrace

The following `bpftrace` command can be used to capture and count all XDP
tracepoints:

```bash
sudo bpftrace -e 'tracepoint:xdp:* { @cnt[probe] = count(); }'
Attaching 12 probes...
^C

@cnt[tracepoint:xdp:mem_connect]: 18
@cnt[tracepoint:xdp:mem_disconnect]: 18
@cnt[tracepoint:xdp:xdp_exception]: 19605
@cnt[tracepoint:xdp:xdp_devmap_xmit]: 1393604
@cnt[tracepoint:xdp:xdp_redirect]: 22292200
```

> **_NOTE:_** The various xdp tracepoints can be found in
> [xdp.h](https://github.com/torvalds/linux/blob/master/include/trace/events/xdp.h)
> in the kernel source tree.

The following `bpftrace` command can be used to extract the ERRNO being returned
as part of the err parameter:

```bash
sudo bpftrace -e \
    'tracepoint:xdp:xdp_redirect*_err {@redir_errno[-args->err] = count();}
tracepoint:xdp:xdp_devmap_xmit {@devmap_errno[-args->err] = count();}'
```

#### perf record

`perf` also supports recording tracepoints:

```bash
perf record -a -e xdp:xdp_redirect_err \
    -e xdp:xdp_redirect_map_err \
    -e xdp:xdp_exception \
    -e xdp:xdp_devmap_xmit
```

## References

- [Debugging Silent Packet Drops](https://docs.kernel.org/bpf/redirect.html#debugging-packet-drops)
- [Capturing network traffic in an eXpress Data Path (XDP) environment](https://www.redhat.com/en/blog/capturing-network-traffic-express-data-path-xdp-environment)
