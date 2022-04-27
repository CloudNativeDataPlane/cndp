#!/bin/bash

# Build CNDP and install (sudo CNE_DEST_DIR=/ make install) before running this script.
# Usage: ./run.sh <json config file (optional)> <port id (optional)> <core id (optional)>
# eg 1: ./run.sh -> Run using default values
# eg 2:./run.sh ../../fwd.json 0 25 -> Run using user specified values.

# JSON file. Use default jsonc file in library crate.
CONFIG=${1:-"../../fwd.jsonc"}

# Port id. Use default port id as 0.
PORT=${2:-0}

# Core affinity for loopback thread. Default value "-1" means core affinity not set.
CORE=${3:-"-1"}

# Need to LD_PRELOAD libpmd_af_xdp.so since Rust binary doesn't include it and is required for applications.
# Including libpmd_af_xdp.so as whole-archive during linking of rust binary doesn't seem to work.
cargo build --release
sudo -E LD_LIBRARY_PATH=$LD_LIBRARY_PATH LD_PRELOAD=$LD_LIBRARY_PATH/libpmd_af_xdp.so RUST_LOG=info `which cargo` run --release -- -c $CONFIG -p $PORT -a $CORE

stty sane
