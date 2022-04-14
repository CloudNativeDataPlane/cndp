### Rust pktfwd

An example CNDP pktfwd application written in Rust. Following are the steps required to run this
application.

1. Install [Rust and Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html)

2. Install clang used by rust bindgen tool: `sudo apt-get install clang`

3. Install CNDP in a location which is searched by the compiler/linker. Do this by building CNDP
normally, then install with `sudo CNE_DEST_DIR=/ make install`

4. Append *PKG_CONFIG_PATH* environment variable to directory containing CNDP pkg-config file.

   `export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/usr/local/lib/pkgconfig`

5. Append LD_LIBRARY_PATH environment variable with CNDP library path.

   `export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib/x86_64-linux-gnu`

6. Build Rust application: From CNDP root directory execute the command `make rust-app`

7. `cd lang/rs/pktfwd`

8. Configure ethtool filter and fwd.jsonc similar to [cndpfwd application](../../INSTALL.md#cndpfwd)

9. Execute the script `./runcmd.sh <option>` where option can be `drop|fwd|tx-only|lb`

### Wireguard with CNDP

Wireguard user space (implemented in Rust) uses CNDP to send and receive packets from/to user space.

1. Clone Wireguard Rust repo : `git clone https://github.com/WireGuard/wireguard-rs.git`

2. `cd wireguard-rs`

3. Checkout the version tested with CNDP: `git checkout 7d84ef9`

4. Apply the Wireguard CNDP patch present in [location](./wireguard/patch). Ignore the whitespace warning errors.

   `git am 0001-Integarte-CNDP-Cloud-Native-Data-Plane-with-Wireguar.patch`\
   `git am 0002-Rename-variable-private-to-priv_-to-fix-build-error.patch`\
   `git am 0003-Remove-extra-argument-from-pktmbuf_dump.patch`

5. Build Wireguard with CNDP: `cargo build --release`
6. In Wireguard repo, refer to *src/platform/linux/cndp/README.md* file under usage section to configure and start Wireguard with CNDP.
