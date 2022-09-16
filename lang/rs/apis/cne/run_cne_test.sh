#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2022 Intel Corporation

# Build CNDP and install (sudo CNE_DEST_DIR=/ make install) before running this script.

CRATE=cndp-cne

# Build (This will do incremental build)
cargo build

sudo -E  LD_LIBRARY_PATH="$LD_LIBRARY_PATH" RUST_LOG=debug "$(which cargo)" test -p "$CRATE" --tests  -- --show-output --test-threads=1

stty sane
