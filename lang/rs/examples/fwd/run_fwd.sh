#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2025 Intel Corporation

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

sudo -E LD_LIBRARY_PATH="$LD_LIBRARY_PATH" RUST_LOG=info "$(which cargo)" run -p "$CRATE" --release -- -c "$CONFIG" "$MODE"

stty sane
