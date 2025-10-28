# CNDP - Cloud Native Data Plane
CNDP is a high-performance packet processing framework using AF_XDP for cloud native applications. It provides userspace libraries to accelerate network processing while maintaining compatibility with standard Linux networking interfaces.

**ALWAYS reference these instructions first and fallback to search or bash commands only when you encounter unexpected information that does not match the info here.**

## Working Effectively

### Bootstrap, Build, and Test
Run these commands to set up the development environment:

1. **Install system dependencies:**
   ```bash
   sudo apt-get update && sudo apt-get install -y \
     build-essential libbsd-dev libelf-dev libjson-c-dev \
     libnl-3-dev libnl-cli-3-dev libnuma-dev libpcap-dev \
     pkg-config wget python3-pip libmosquitto-dev
   ```

2. **Install Meson build system:**
   ```bash
   python3 -m pip install --upgrade pip
   pip install --user meson
   echo "$HOME/.local/bin" >> "$HOME/.bashrc"
   export PATH="$HOME/.local/bin:$PATH"
   ```

3. **Install libbpf dependency (required for AF_XDP):**
   ```bash
   wget -q -O - https://github.com/libbpf/libbpf/archive/refs/tags/v0.5.0.tar.gz | tar -xzC /tmp
   sudo make -j -C /tmp/libbpf-0.5.0/src install
   sudo rm -rf /tmp/libbpf-0.5.0
   echo "/usr/lib64" | sudo tee -a /etc/ld.so.conf.d/x86_64-linux-gnu.conf
   sudo ldconfig
   export PKG_CONFIG_PATH="/usr/lib64/pkgconfig:$PKG_CONFIG_PATH"
   ```

4. **Build CNDP:**
   ```bash
   make
   ```
   - **NEVER CANCEL:** Build takes ~40-45 seconds. Set timeout to 120+ seconds.
   - The build system uses Meson with a Makefile wrapper via `tools/cne-build.sh`

5. **Run tests:**
   ```bash
   meson test -C builddir --suite short
   ```
   - **NEVER CANCEL:** Test suite takes ~4-5 seconds. Set timeout to 30+ seconds.
   - Tests validate core functionality including memory pools, packet processing, and networking components

### Environment Setup Commands
Always run these exports before building:
```bash
export PATH="$HOME/.local/bin:$PATH"
export PKG_CONFIG_PATH="/usr/lib64/pkgconfig:$PKG_CONFIG_PATH"
```

### Build Variations
- `make rebuild` - Clean and rebuild (takes ~38 seconds)
- `make clean` - Clean build artifacts (takes ~1 second)
- `make debug` - Build debug version with -O0
- `make static_build=1` - Build static libraries
- `make tcp=1` - Enable TCP support
- `make ipv6=1` - Enable IPv6 support

## Testing and Validation

### Example Applications
Always test functionality after making changes:

1. **helloworld (basic validation):**
   ```bash
   timeout 5s ./builddir/examples/helloworld/helloworld
   ```
   Expected output: "hello world! thread id 1" and clean exit

2. **cndpfwd (network processing):**
   Requires network interface configuration. Edit `examples/cndpfwd/fwd.jsonc` before running:
   ```bash
   sudo ./builddir/examples/cndpfwd/cndpfwd -c examples/cndpfwd/fwd.jsonc drop
   ```

3. **CLI example:**
   ```bash
   ./builddir/examples/cli/cli
   ```

### Manual Validation Scenarios
After making changes, ALWAYS:
1. Run `make` to build successfully
2. Run `meson test -C builddir --suite short` to validate core functionality
3. Test at least the helloworld example to ensure runtime works
4. For networking changes, test cndpfwd with appropriate configuration

## Code Quality and Formatting

### Pre-commit and Formatting
```bash
pip install --user pre-commit
ninja -C builddir clang-format
```
- **ALWAYS** run `ninja -C builddir clang-format` before committing
- CI will fail if code is not properly formatted
- Pre-commit hooks exist but may have dependency issues

### Documentation Generation
```bash
sudo apt-get install -y doxygen python3-sphinx
make docs
```

## Repository Structure

### Key Directories
```
├── lib/                  # Core CNDP libraries
│   ├── common/          # Common utilities and helpers
│   ├── core/            # Core CNDP functionality
│   ├── cnet/            # Network stack implementation
│   ├── include/         # Public API headers
│   └── usr/             # User-space libraries
├── examples/            # Example applications and demos
│   ├── helloworld/      # Basic "hello world" example
│   ├── cndpfwd/         # Packet forwarding example
│   ├── cli/             # Command-line interface example
│   └── l3fwd-graph/     # Layer 3 forwarding with graph
├── test/                # Test framework and unit tests
│   ├── testcne/         # Main test application
│   └── common/          # Common test utilities
├── tools/               # Build and development tools
│   └── cne-build.sh     # Main build script (Meson wrapper)
└── usrtools/            # User tools
    ├── cnectl/          # Remote CLI tool
    └── txgen/           # Traffic generator
```

### Important Files
- `Makefile` - Main build interface (wrapper around tools/cne-build.sh)
- `meson.build` - Meson build configuration
- `tools/cne-build.sh` - Core build script with all build logic
- `.clang-format` - Code formatting rules
- `examples/cndpfwd/fwd.jsonc` - Main configuration for networking examples

## Common Tasks

### Build Environment Check
```bash
# Verify dependencies
which meson ninja pkg-config
pkg-config --modversion libbpf
```

### Timing Expectations (NEVER CANCEL)
- **Initial build:** ~40-45 seconds (timeout: 120s)
- **Rebuild (clean + build):** ~38-40 seconds (timeout: 120s)
- **Test suite:** ~4-5 seconds (timeout: 30s)
- **Clean:** ~1 second
- **Documentation:** ~1 second (if sphinx/doxygen installed)

### Build Artifacts Location
- Executables: `builddir/examples/*/`
- Libraries: `builddir/lib/`
- Test logs: `builddir/meson-logs/testlog.txt`

## Troubleshooting

### Common Issues
1. **Missing libbpf:** Install from source using the exact commands above
2. **Meson not found:** Ensure `$HOME/.local/bin` is in PATH
3. **Build fails:** Check PKG_CONFIG_PATH includes `/usr/lib64/pkgconfig`
4. **Tests fail:** Ensure system has sufficient permissions for memory operations

### Dependency Validation
AF_XDP support requires kernel CONFIG_XDP_SOCKETS=y:
```bash
grep XDP_SOCKETS= /boot/config-$(uname -r)
```

### Network Interface Requirements
For networking examples, configure ethtool filters:
```bash
sudo ethtool -N <devname> flow-type udp4 dst-port <dport> action <qid>
sudo ip link set dev <devname> up
```

## Development Workflow
1. Make changes to source code
2. Run `ninja -C builddir clang-format` to format code
3. Run `make` to build (NEVER CANCEL - wait 45+ seconds)
4. Run `meson test -C builddir --suite short` to test (NEVER CANCEL - wait 5+ seconds)
5. Test relevant examples manually
6. Commit changes

Always build and test before submitting changes to ensure CI pipeline passes.
