# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CNDP (Cloud Native Data Plane) is a collection of userspace libraries for accelerating packet processing in cloud applications. It leverages AF_XDP for direct kernel-bypass packet delivery to userspace — simpler than DPDK (no hugepages, no custom drivers, no PCI bus scanning). Version: 25.08.0.

## Build Commands

The build system is **Meson + Ninja**, wrapped by a top-level `Makefile` that calls `tools/cne-build.sh`.

```bash
make                        # Release build (builddir/)
make debug                  # Debug build
make debugopt               # Debug with -O2
make rebuild                # Clean + rebuild
make install                # Install to usr/local
make uninstall
make clean

# Feature toggles (passed as environment variables to make)
make tcp=1 build            # Enable experimental TCP support
make ipv6=1 build           # Enable experimental IPv6
make static_build=1 build   # Build static libraries
make V=1 build              # Verbose output

make docs                   # Generate Doxygen API docs
make rust-app               # Build Rust language bindings
make oci-image              # Build Docker image
```

Direct meson/ninja usage:
```bash
meson setup builddir                  # Initial configure
ninja -C builddir                     # Build
sudo ninja -C builddir install        # Install
```

## Running Tests

Tests require root (AF_XDP socket creation). The test harness is `builddir/test/testcne/test-cne`.

```bash
# Run the short CI suite
meson test -C builddir --suite short

# Run all tests
meson test -C builddir

# Run a single named test
sudo ./builddir/test/testcne/test-cne -- mempool
sudo ./builddir/test/testcne/test-cne -- ring
sudo ./builddir/test/testcne/test-cne -- mbuf
```

Available test names (65+): `acl`, `cne_register`, `cthread`, `dsa`, `fib`, `fib6`, `graph`, `hash`, `hmap`, `ibroker`, `idlemgr`, `jcfg`, `kvargs`, `log`, `loop`, `mbuf`, `mempool`, `meter`, `metrics`, `mmap`, `msgchan`, `pkt`, `pktcpy`, `pktdev`, `rib`, `rib6`, `ring`, `tailqs`, `thread`, `timer`, `txbuff`, `uid`, `vec`, `xskdev`.

## Code Style and Linting

```bash
# Install pre-commit hooks (run once)
pip install pre-commit && pre-commit install

# Run all hooks manually
pre-commit run --all-files

# Format a single file
clang-format -i --style=file <file>
```

- **C formatting**: clang-format, LLVM-based style, 100-character column limit (see `.clang-format`)
- **YAML**: yamllint (see `.yamllint.yaml`)
- **Spelling**: codespell (see `cndp-codespell.precommit-toml`)
- Pre-commit runs clang-format automatically on commit; CI enforces it via `.github/workflows/pre-commit.yml`

## Architecture

### Core Subsystems

**I/O Layer** (`lib/core/pmds/`, `lib/core/xskdev/`, `lib/core/pktdev/`): AF_XDP packet device abstraction. `xskdev` is the low-level AF_XDP interface; `pktdev` is the higher-level device API used by applications. PMDs (Poll Mode Drivers) in `pmds/` include `af_xdp`, `memif`, and `null` backends.

**Memory Management** (`lib/core/mempool/`, `lib/core/pktmbuf/`, `lib/core/ring/`, `lib/core/mmap/`): Zero-copy packet buffer lifecycle. `pktmbuf` wraps raw memory into structured packet buffers; `mempool` provides per-lcore object pools; `ring` is the lockless MPMC queue used throughout.

**Network Stack** (`lib/cnet/`): Optional full userspace TCP/IP stack (27 subdirectories). Enabled at build time via `tcp=1` and `ipv6=1`. Provides channels, TCBs, routes, ARP, and socket-like APIs.

**Data Structures** (`lib/core/hash/`, `lib/core/fib/`, `lib/core/rib/`, `lib/core/acl/`, `lib/core/graph/`): High-performance lookup structures. `graph` is a node-based packet processing pipeline (similar to DPDK's rte_graph).

**System Abstraction** (`lib/core/osal/`): OS abstraction (thread affinity, timers, CPU topology). Provides `cne_lcore` thread model.

**Utilities** (`lib/core/kvargs/`, `lib/core/log/`, `lib/core/metrics/`, `lib/core/msgchan/`, `lib/core/idlemgr/`, `lib/core/timer/`): Support libraries used across core and applications.

### Language Bindings

**Rust** (`lang/rs/`): Cargo workspace with two crates:
- `bindings/cne-sys/` — raw `bindgen`-generated FFI to the C library
- `apis/cne/` — safe high-level Rust API wrapping `cne-sys`
- Examples: `echo_server`, `fwd`, `loopback`, `wireguard`

**Go** (`lang/go/`): Work-in-progress Go bindings.

### Application Pattern

Applications (in `examples/`) follow this pattern:
1. Parse JSON config (`jcfg`) defining lports, threads, and lcore assignments
2. Initialize `pktdev` ports
3. Launch per-lcore threads via the `cne` framework
4. Process packets in tight loops using `pktmbuf` / `graph` nodes

### Configuration

Runtime configuration uses JSON files (parsed by `lib/core/jcfg/`). See examples in `examples/*/` for `.jsonc` config files showing lport, thread, and lcore setup.

## CI/CD

GitHub Actions workflows:
- `smoke.yml` — build + `meson test --suite short` on every PR
- `cppcheck.yaml` — static analysis
- `pre-commit.yml` — formatting enforcement
- `rust-build.yml` — Rust bindings build
- `docker.yml` — container image builds

## Key Dependencies

Required: `libbsd`, `libelf`, `libjson-c`, `libnl-3`, `libnuma`, `libpcap`
Optional: `libxdp`/`libbpf` (enhanced AF_XDP), `libdlb` (Intel DLB), `picotls`+`quicly` (QUIC examples)
Build tools: Meson ≥ 1.5.0, Ninja, GCC/Clang with C11 support, Python 3
