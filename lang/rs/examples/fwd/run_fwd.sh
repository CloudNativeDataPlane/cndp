#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2022 Intel Corporation

# Usage: ./run_fwd.sh <json config file (optional)> [[drop | rx-only], tx-only, [fwd | forward], [lb | loopback]]
# eg 1: ./run_fwd.sh -> Run using default values
# eg 2: ./run_fwd.sh ./fwd.jsonc lb -> Run using user specified values.

CRATE=fwd

# Build (This will do incremental build)
cargo build --release

# JSON file. Use default jsonc file in library crate.
CONFIG=${1:-"./fwd.jsonc"}

# Mode - drop,rx-only,tx-only,lb,fwd. Default is drop.
MODE=${2:-"drop"}

# Need to LD_PRELOAD libpmd_af_xdp.so since Rust binary doesn't include it and is required for applications.
# Including libpmd_af_xdp.so as whole-archive during linking of rust binary doesn't seem to work.
sudo -E LD_LIBRARY_PATH="$LD_LIBRARY_PATH" LD_PRELOAD="$LD_LIBRARY_PATH"/libpmd_af_xdp.so RUST_LOG=info "$(which cargo)" run -p "$CRATE" --release -- -c "$CONFIG" "$MODE"

stty sane
