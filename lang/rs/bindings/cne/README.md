# Cloud Native Data Plane (CNDP) Rust API Interface

High-level Rust API interface for CNDP C library.

Following are the steps required to build this library and run test cases.

1. Build CNDP and cne-sys Rust bindings. Refer cne-sys [INSTALL.md](../cne-sys/INSTALL.md)
2. `cd lang/rs/bindings/cne`
3.  Configure ethtool filter and fwd.jsonc similar to [cndpfwd application](https://github.com/CloudNativeDataPlane/cndp/blob/main/INSTALL.md#cndpfwd)

4. Execute the script `./run_test.sh` . This will build CNDP Rust bindings library and run tests. Running tests need sudo privileges.

