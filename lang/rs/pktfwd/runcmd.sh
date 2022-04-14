# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2022 Intel Corporation.

#!/bin/bash
BUILD=release
# Need to LD_PRELOAD libpmd_af_xdp.so since Rust binary doesn't include it and is required for CNDP applications.
# Including libpmd_af_xdp.so as whole-archive during linking of rust binary doesn't seem to work.
# Usage: ./runcmd.sh drop|fwd|tx-only
sudo LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./build LD_PRELOAD=$LD_LIBRARY_PATH/libpmd_af_xdp.so ./target/$BUILD/pktfwd -c ./fwd.jsonc $1
