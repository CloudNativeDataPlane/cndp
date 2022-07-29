# Rust CNE Bindings, High Level API and Example Applications

Rust bindings for CNDP CNE C library.

Following are the steps required to build Rust bindings, high level APIs and example applications.

1. Build CNDP. Refer CNDP [INSTALL.md](https://github.com/CloudNativeDataPlane/cndp/blob/main/INSTALL.md)

2. Install CNDP.

    1. To install CNDP in the directory from where CNDP was built, use the command `make install`.

    2. To install CNDP in a system wide path, use the command `sudo CNE_DEST_DIR=/ make install`.
       This will install CNDP under `/usr/local` directory.

    3. Append *PKG_CONFIG_PATH* environment variable to directory containing CNDP pkg-config file.
       This step is optional. This is required if pkg-config is used to resolve CNDP dependencies
       when building applications/libraries.

        `export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/usr/local/lib/pkgconfig`

    4. Append LD_LIBRARY_PATH environment variable with CNDP library path.

        `export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib/x86_64-linux-gnu`

3. Install [Rust and Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html). Rust version >= 1.56.0 is required.

4. Install dependencies needed by rust bindgen tool. Please refer rust bindgen [requirements](https://rust-lang.github.io/rust-bindgen/requirements.html) for details.

   `sudo apt-get install llvm-dev libclang-dev clang`

5. `cd lang/rs`

6. Build:
   1. If CNDP is installed in a system wide path run `cargo build`.
   2. If CNDP is installed in a custom location run `CNDP_INSTALL_PATH=<path> cargo build`.
      Here path refers to the absolute path of top-level directory where CNDP is installed.

7. Execute tests.
    1. Configure ethtool filter and fwd.jsonc file referred in the script similar to [cndpfwd application](https://github.com/CloudNativeDataPlane/cndp/blob/main/INSTALL.md#cndpfwd)
    2. Run CNE tests:  `cd apis/cne`. Execute [./run_cne_test.sh](./run_cne_test.sh).

8. Run example applications.
   1. To get best performance build in release mode: `cargo build --release`.
   2. Configure ethtool filter and fwd.jsonc file referred in the script similar to [cndpfwd application](https://github.com/CloudNativeDataPlane/cndp/blob/main/INSTALL.md#cndpfwd)
   3. Refer the script for details on command line options which can be passed when running the script.
      If no command line options are passed, the script will be executed with default values used in the script.
   4. Run loopback example:  `cd apis/cne`. Execute [./run_loopback.sh](./run_loopback.sh)
   5. Run echo server example: `cd examples/echo_server`. Execute [./run_echo_server.sh](./run_echo_server.sh)
   6. Run packet forward example: `cd examples/fwd`. Execute [./run_fwd.h](./run_fwd.h) `<JSONC config file>` `[[drop | rx-only], tx-only, [fwd | forward], [lb | loopback]]`

9. To generate high level API crate documentation execute [./generate_cne_docs.sh](./generate_cne_docs.sh)

## Wireguard with CNDP

Wireguard user space (implemented in Rust) uses CNDP to send and receive packets from/to user space.

1. Clone Wireguard Rust repo : `git clone https://github.com/WireGuard/wireguard-rs.git`

2. `cd wireguard-rs`

3. Checkout the version tested with CNDP: `git checkout 7d84ef9`

4. Apply the Wireguard CNDP patch present in [location](./wireguard/patch). Ignore the whitespace warning errors.

   `git am *.patch`

5. Build Wireguard with CNDP: `cargo build --release`
6. In Wireguard repo, refer to *src/platform/linux/cndp/README.md* file under usage section to configure and start Wireguard with CNDP.
