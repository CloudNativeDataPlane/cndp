#!/bin/bash

# Usage: ./run.sh <mode> <args>
# if mode is pnet then
# ./run.sh pnet <interface name>
# eg 1: ./run.sh pnet enp134s0

# if mode is cne then 
# ./run.sh cne <json config file (optional)> <port id (optional)> <burst (optional)>
# eg 1: ./run.sh cne -> Run using default values
# eg 2:./run.sh cne ./fwd.jsonc 0 64 -> Run using user specified values.

cargo build --release

# Mode - pnet or cne. Default is cne.
MODE=${1:-"cne"}

if [[ "$MODE" == "pnet" ]]; then
    # interface name.
    IFACE=${2:-"enp134s0"}

    sudo -E RUST_LOG=info `which cargo` run --release -- $MODE -i $IFACE
elif [ "$MODE" == "cne" ]; then
    # JSON file. Use default jsonc file in library crate.
    CONFIG=${2:-"fwd.jsonc"}

    # Port id. Use 0 as default port id.
    PORT=${3:-0}

    # Port id. Use 256 as default burst size.
    BURST=${4:-256}

    # Need to LD_PRELOAD libpmd_af_xdp.so since Rust binary doesn't include it and is required for applications.
    # Including libpmd_af_xdp.so as whole-archive during linking of rust binary doesn't seem to work.
    sudo -E LD_LIBRARY_PATH=$LD_LIBRARY_PATH LD_PRELOAD=$LD_LIBRARY_PATH/libpmd_af_xdp.so RUST_LOG=info `which cargo` run --release -- $MODE -c $CONFIG -p $PORT -b $BURST
else
    cargo run --release -- help
fi

stty sane
