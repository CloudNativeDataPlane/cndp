#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2022 Intel Corporation

# Build CNDP and install (sudo CNE_DEST_DIR=/ make install) before running this script.

# Need to LD_PRELOAD libpmd_af_xdp.so since Rust binary doesn't include it and is required for CNDP applications.
# Including libpmd_af_xdp.so as whole-archive during linking of rust binary doesn't seem to work.
CRATE=cndp-cne
sudo -E  LD_LIBRARY_PATH=$LD_LIBRARY_PATH LD_PRELOAD=$LD_LIBRARY_PATH/libpmd_af_xdp.so RUST_LOG=debug `which cargo` test -p $CRATE --tests  -- --show-output --test-threads=1

stty sane
