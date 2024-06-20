# Cloud Native Data Plane (CNDP) Rust High Level API Interface

High-level Rust API interface for CNDP C library.

Following are the steps required to build this library and run test cases.

1. Build CNDP. Refer CNDP
   [INSTALL.md](https://github.com/CloudNativeDataPlane/cndp/blob/main/INSTALL.md)

1. Install CNDP.

   1. To install CNDP in the directory from where CNDP was built, use the
      command `make install`.
   1. To install CNDP in a system wide path, use the command
      `sudo CNE_DEST_DIR=/ make install`. This will install CNDP under
      `/usr/local` directory.
   1. Append *PKG_CONFIG_PATH* environment variable to directory containing CNDP
      pkg-config file. This step is optional. This is required if pkg-config is
      used to resolve CNDP dependencies when building applications /libraries.

    `export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/usr/local/lib/pkgconfig`

   1. Append LD_LIBRARY_PATH environment variable with CNDP library path.

   Ubuntu:`export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib/x86_64-linux-gnu`
   Fedora:`export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib64`

1. This crate depends on cne-sys crate which uses Rust bindgen tool. Install
   dependencies needed by rust bindgen tool. Please refer rust bindgen
   [requirements](https://rust-lang.github.io/rust-bindgen/requirements.html)
   for details.

   Ubuntu:`sudo apt-get install llvm-dev libclang-dev clang`
   Fedora:`dnf install clang-devel`

1. `cd lang/rs/apis/cne`

1. Build CNE Rust high level crate. Rust version >= 1.63.0 is required.

   1. If CNDP is installed in a system wide path run `cargo build`.
   1. If CNDP is installed in a custom location run
      `CNDP_INSTALL_PATH=<path> cargo build`. Here path refers to the absolute
      path of top-level directory where CNDP is installed.

1. Configure ethtool filter and fwd.jsonc similar to
   [cndpfwd application](https://github.com/CloudNativeDataPlane/cndp/blob/main/INSTALL.md#cndpfwd)

1. Execute the test script [./rust_cne_test.sh](./run_cne_test.sh). Running
   tests need sudo privileges.

1. Run loopback example:

   1. To get best performance build in release mode: `cargo build --release`.
   1. Configure ethtool filter and fwd.jsonc file referred in the script similar
      to
      [cndpfwd application](https://github.com/CloudNativeDataPlane/cndp/blob/main/INSTALL.md#cndpfwd)
   1. Refer the script for details on command line options which can be passed
      when running the script. If no command line options are passed, the script
      will be executed with default values used in the script.
   1. Execute [./run_loopback.sh](./run_loopback.sh).
