#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2022 Intel Corporation

# Build CNDP and install (sudo CNE_DEST_DIR=/ make install) before running this script.
# Usage: ./run_loopback.sh <json config file (optional)> <port id (optional)> <core id (optional)>
# eg 1: ./run_loopback.sh -> Run using default values
# eg 2:./run_loopback.sh ../../fwd.json 0 25 -> Run using user specified values.
CRATE=loopback

# Build (This will do incremental build)
cargo build --release

# JSON file. Use default jsonc file in library crate.
CONFIG=${1:-"./fwd.jsonc"}

# Port id. Use default port id as 0.
PORT=${2:-0}

# Core affinity group for loopback thread. Default value "" means core affinity will not be set.
# group name should be present in lcore-groups in jsonc file.
CORE=${3:-"group0"}

# Need to LD_PRELOAD libpmd_af_xdp.so since Rust binary doesn't include it and is required for applications.
# Including libpmd_af_xdp.so as whole-archive during linking of rust binary doesn't seem to work.
sudo -E LD_LIBRARY_PATH="$LD_LIBRARY_PATH" LD_PRELOAD="$LD_LIBRARY_PATH"/libpmd_af_xdp.so RUST_LOG=info "$(which cargo)" run -p "$CRATE" --release -- -c "$CONFIG" -p "$PORT" -a "$CORE"

stty sane
