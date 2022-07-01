# Cloud Native Data Plane (CNDP) Rust Bindings

Rust bindings for CNDP CNE C library.

Following are the steps required to build this library and run test cases.

1. Build CNDP. Refer CNDP [INSTALL.md](https://github.com/CloudNativeDataPlane/cndp/blob/main/INSTALL.md)

2. Install CNDP.

    1. To install CNDP in the directory from where CNDP was built, use the command `make install`.
    2. To install CNDP in a system wide path, use the command `sudo CNE_DEST_DIR=/ make install`.
       This will install CNDP under `/usr/local` directory.
    3. Append *PKG_CONFIG_PATH* environment variable to directory containing CNDP pkg-config file.
       This step is optional. This is required if pkg-config is used to resolve CNDP dependencies
       when building applications/libraries.

    ​       `export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/usr/local/lib/pkgconfig`

    4. Append LD_LIBRARY_PATH environment variable with CNDP library path.

    ​       `export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib/x86_64-linux-gnu`

3. Install dependencies needed by rust bindgen tool. Please refer rust bindgen [requirements](https://rust-lang.github.io/rust-bindgen/requirements.html) for details.
   `sudo apt-get install llvm-dev libclang-dev clang`

4. `cd lang/rs/bindings/cne-sys`

5. Build CNE Rust bindings library. Rust version >= 1.56.0 is required.
   1. If CNDP is installed in a system wide path run `cargo build`
   2. If CNDP is installed in a custom location run `CNDP_INSTALL_PATH=<path> cargo build`.
      Here path refers to the absolute path of top-level directory where CNDP is installed.

6. Run tests: `cargo test`
