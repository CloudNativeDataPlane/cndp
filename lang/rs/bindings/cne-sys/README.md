# Cloud Native Data Plane (CNDP) Rust Bindings

Rust bindings for CNDP CNE C library.

Following are the steps required to build this library and run test cases.

1. Build CNDP. Refer CNDP [INSTALL.md](https://github.com/CloudNativeDataPlane/cndp/blob/main/INSTALL.md)

2. Install dependencies needed by rust bindgen tool: `sudo apt-get install llvm-dev libclang-dev clang`. Please refer rust bindgen [requirements](https://rust-lang.github.io/rust-bindgen/requirements.html) for details.

3. Install CNDP in a location which is searched by the compiler/linker. Do this by building CNDP
    normally, then install with `sudo CNE_DEST_DIR=/ make install`.  This will install CNDP under `/usr/local` directory. Steps 3a and 3b below are optional. This is required if CNDP is installed in non default location.

      a. Append *PKG_CONFIG_PATH* environment variable to directory containing CNDP pkg-config file.

      `export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/usr/local/lib/pkgconfig`

      b. Append LD_LIBRARY_PATH environment variable with CNDP library path.

      `export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib/x86_64-linux-gnu`

4. `cd lang/rs/bindings/cne-sys`

5. Build : `cargo build`.

6. Run tests: `cargo test`

